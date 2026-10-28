#include "collector.h"
#include <QFile>
#include <QJsonDocument>
#include <QNetworkDatagram>
#include <QRegularExpression>
#include <QTimer>
namespace siem {
Collector::Collector(Store &s, QObject *p) : QObject(p), store_(s) {
    connect(&socket_, &QUdpSocket::readyRead, this, &Collector::drain);
}
bool Collector::start(quint16 port, QString *error) {
    stop();
    if (!socket_.bind(QHostAddress::LocalHost, port, QUdpSocket::DontShareAddress)) {
        *error = socket_.errorString();
        return false;
    }
    store_.audit("collector.start", QString("127.0.0.1:%1/udp").arg(socket_.localPort()));
    return true;
}
void Collector::stop() {
    socket_.close();
}
void Collector::drain() {
    for (int n = 0; n < 100 && socket_.hasPendingDatagrams(); ++n) {
        const auto d = socket_.receiveDatagram(16384);
        try {
            store_.ingest(parse(d.data(), d.senderAddress().toString()));
        } catch (const std::exception &e) {
            emit error(QString::fromUtf8(e.what()));
        }
    }
    if (socket_.hasPendingDatagrams())
        QTimer::singleShot(0, this, &Collector::drain);
}
Event Collector::parse(const QByteArray &data, const QString &sender, const QString &source) {
    Event e;
    e.source = source;
    e.host = sender;
    e.ip = QHostAddress(sender).isNull() ? QString() : sender;
    auto doc = QJsonDocument::fromJson(data);
    if (doc.isObject()) {
        auto j = doc.object();
        e.raw = j;
        e.source = j.value("source").toString(source).left(128);
        e.host = j.value("host").toString(sender).left(256);
        e.ip = j.value("src_ip").toString(j.value("ip").toString(e.ip));
        if (j.contains("src_ip") && !j.contains("host"))
            e.host = e.ip;
        e.message = j.value("message").toString(QString::fromUtf8(data));
        e.category = j.value("category").toString(j.value("event_type").toString("log"));
        e.severity = j.value("severity").toString("info");
        if (j.value("alert").isObject()) {
            auto a = j["alert"].toObject();
            e.message = a["signature"].toString(e.message);
            int s = a["severity"].toInt(3);
            e.severity = s <= 1 ? "critical" : s == 2 ? "high" : "medium";
            e.source = "Suricata";
        }
        auto dt = QDateTime::fromString(j.value("timestamp").toString(j.value("time").toString()),
                                        Qt::ISODateWithMs);
        if (dt.isValid())
            e.time = dt;
    } else {
        e.message = QString::fromUtf8(data).trimmed();
        e.category = "syslog";
        const auto m = QRegularExpression("^<(\\d{1,3})>").match(e.message);
        if (m.hasMatch()) {
            int pri = m.captured(1).toInt();
            e.severity = pri % 8 <= 2 ? "critical" : pri % 8 == 3 ? "high" : pri % 8 == 4 ? "medium" : "info";
            e.message.remove(0, m.capturedLength());
        }
        // RFC5424: version timestamp hostname app procid msgid structured-data msg.
        const auto r =
            QRegularExpression("^1 ([^ ]+) ([^ ]+) ([^ ]+) ([^ ]+) ([^ ]+) (.*)$").match(e.message);
        if (r.hasMatch()) {
            if (r.captured(2) != "-")
                e.host = r.captured(2);
            auto dt = QDateTime::fromString(r.captured(1), Qt::ISODateWithMs);
            if (dt.isValid())
                e.time = dt;
            e.message = r.captured(6);
        }
    }
    if (!QStringList{"info", "low", "medium", "high", "critical"}.contains(e.severity))
        e.severity = "info";
    e.message = e.message.left(16384);
    return e;
}
int Collector::importFile(const QString &path, QString *error) {
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        *error = f.errorString();
        return 0;
    }
    if (f.size() > 20 * 1024 * 1024) {
        *error = "Лимит импорта — 20 МБ. Разделите файл на части.";
        return 0;
    }
    int n = 0;
    while (!f.atEnd()) {
        auto line = f.readLine(65537);
        if (line.size() > 65536) {
            *error = "Строка превышает 64 КБ. Импорт остановлен.";
            break;
        }
        if (line.trimmed().isEmpty())
            continue;
        store_.ingest(parse(line, "import", "Файл"));
        ++n;
    }
    store_.audit("events.import", QString("%1: %2 записей").arg(path).arg(n));
    return n;
}
} // namespace siem
