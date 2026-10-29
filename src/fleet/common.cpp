#include "common.h"
#include "core/firewall.h"
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QSaveFile>
#include <QSslCertificate>
#include <QSslKey>
#include <QSslSocket>
#include <QUuid>
#include <stdexcept>

namespace siem::fleet {
QString now() { return QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs); }
QString uuid() { return QUuid::createUuid().toString(QUuid::WithoutBraces); }
QString digest(const QByteArray &v) { return QString::fromLatin1(QCryptographicHash::hash(v, QCryptographicHash::Sha256).toHex()); }
void require(bool c, const QString &message) { if (!c) throw std::runtime_error(message.toStdString()); }
QByteArray readFile(const QString &path, qint64 limit) {
    QFile f(path);
    require(f.open(QIODevice::ReadOnly), "Cannot read: " + path);
    require(f.size() <= limit, "File exceeds size limit: " + path);
    return f.readAll();
}
QJsonObject readObject(const QString &path) {
    QJsonParseError error;
    auto doc = QJsonDocument::fromJson(readFile(path), &error);
    require(error.error == QJsonParseError::NoError && doc.isObject(), "Invalid JSON: " + path);
    return doc.object();
}
void writePrivate(const QString &path, const QByteArray &data) {
    require(QDir().mkpath(QFileInfo(path).absolutePath()), "Cannot create configuration directory");
    QSaveFile f(path);
    require(f.open(QIODevice::WriteOnly), "Cannot write: " + path);
    require(f.setPermissions(QFile::ReadOwner | QFile::WriteOwner), "Cannot protect: " + path);
    require(f.write(data) == data.size() && f.commit(), "Cannot commit: " + path);
}
QString certificateId(const QString &path) {
    const auto certs = QSslCertificate::fromData(readFile(path));
    require(!certs.isEmpty(), "Invalid certificate: " + path);
    return digest(certs.first().toDer());
}
QSslConfiguration tlsConfiguration(const QJsonObject &c) {
    require(QSslSocket::supportsSsl(), "TLS backend unavailable");
    auto cfg = QSslConfiguration::defaultConfiguration();
    auto ca = QSslCertificate::fromData(readFile(c["ca"].toString()));
    auto chain = QSslCertificate::fromData(readFile(c["certificate"].toString()));
    auto bytes = readFile(c["private_key"].toString());
    QSslKey key(bytes, QSsl::Rsa);
    if (key.isNull()) key = QSslKey(bytes, QSsl::Ec);
    require(!ca.isEmpty() && !chain.isEmpty() && !key.isNull(), "Invalid TLS identity");
    cfg.setCaCertificates(ca); // Trust only the deployment CA, not unrelated public roots.
    cfg.setLocalCertificateChain(chain);
    cfg.setPrivateKey(key);
    cfg.setProtocol(QSsl::TlsV1_2OrLater);
    cfg.setPeerVerifyMode(QSslSocket::VerifyPeer);
    cfg.setPeerVerifyDepth(4);
    cfg.setSslOption(QSsl::SslOptionDisableSessionTickets, true);
    return cfg;
}
DatabaseConfig databaseConfig(const QJsonObject &c) {
    DatabaseConfig d;
    d.host = c["host"].toString("127.0.0.1"); d.port = c["port"].toInt(5432);
    d.name = c["name"].toString("sentinel"); d.user = c["user"].toString("sentinel");
    d.password = c.contains("password_file") ? QString::fromUtf8(readFile(c["password_file"].toString(), 4096)).trimmed()
                                             : qEnvironmentVariable("SIEM_DB_PASSWORD");
    return d;
}
QJsonObject eventJson(const Event &e) {
    return {{"timestamp", e.time.toUTC().toString(Qt::ISODateWithMs)}, {"source",e.source}, {"host",e.host},
            {"category",e.category}, {"severity",e.severity}, {"message",e.message}, {"ip",e.ip}, {"raw",e.raw}};
}
QString nativeBackend() {
#ifdef Q_OS_WIN
    return "windows";
#else
    return "linux";
#endif
}
QJsonObject defaultEndpointPolicy() {
    return {{"firewall", QJsonObject{}}, {"antivirus", QJsonObject{{"enabled",false},{"paths",QJsonArray{}},
             {"exclusions",QJsonArray{}},{"interval_minutes",1440}}}};
}
QString validateEndpointPolicy(const QJsonObject &p) {
    for (auto it = p.begin(); it != p.end(); ++it)
        if (!QStringList{"firewall","antivirus"}.contains(it.key())) return "Unknown policy field: " + it.key();
    if (!p["firewall"].isObject() || !p["antivirus"].isObject()) return "firewall and antivirus objects are required";
    const auto fw = p["firewall"].toObject();
    for (auto it = fw.begin(); it != fw.end(); ++it) {
        if (!QStringList{"linux","windows","dpdk"}.contains(it.key()) || !it.value().isObject()) return "Unknown firewall backend";
        auto value = it.value().toObject();
        auto e = it.key() == "linux" ? validateNftPolicy(value) : it.key() == "windows" ? validateWindowsPolicy(value) : validateDpdkPolicy(value);
        if (!e.isEmpty()) return it.key() + ": " + e;
    }
    const auto av = p["antivirus"].toObject();
    for (auto it = av.begin(); it != av.end(); ++it)
        if (!QStringList{"enabled","paths","exclusions","interval_minutes"}.contains(it.key())) return "Unknown antivirus field";
    if (!av["enabled"].isBool() || !av["paths"].isArray() || !av["exclusions"].isArray()) return "Invalid antivirus settings";
    if (av["interval_minutes"].toInt() < 5 || av["interval_minutes"].toInt() > 43200) return "Scan interval must be 5–43200 minutes";
    if (av["paths"].toArray().size() > 32 || av["exclusions"].toArray().size() > 64) return "Too many scan paths";
    for (const auto &key : {"paths", "exclusions"})
        for (const auto &v : av[key].toArray())
            if (!v.isString() || v.toString().isEmpty() || v.toString().size() > 1024 || v.toString().contains(QChar('\0')))
                return "Invalid scan path";
    return {};
}
}
