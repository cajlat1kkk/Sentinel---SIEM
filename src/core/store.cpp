#include "store.h"
#include <QDir>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QSqlError>
#include <QSqlQuery>
#include <QSqlRecord>
#include <QUuid>
#include <stdexcept>

namespace siem {
static void check(bool ok, const QSqlQuery &q) {
    if (!ok)
        throw std::runtime_error(q.lastError().text().toStdString());
}
Store::Store(const QString &path, QObject *parent)
    : QObject(parent), connection_(QUuid::createUuid().toString()), path_(path) {
    QDir().mkpath(QFileInfo(path).absolutePath());
    db_ = QSqlDatabase::addDatabase("QSQLITE", connection_);
    db_.setDatabaseName(path);
    if (!db_.open())
        throw std::runtime_error(db_.lastError().text().toStdString());
    exec("PRAGMA journal_mode=WAL");
    exec("PRAGMA foreign_keys=ON");
    exec("PRAGMA busy_timeout=5000");
    initialize();
}
Store::Store(const DatabaseConfig &c, QObject *parent)
    : QObject(parent), connection_(QUuid::createUuid().toString()),
      path_(QString("PostgreSQL · %1:%2/%3").arg(c.host).arg(c.port).arg(c.name)) {
    db_ = QSqlDatabase::addDatabase("QPSQL", connection_);
    db_.setHostName(c.host);
    db_.setPort(c.port);
    db_.setDatabaseName(c.name);
    db_.setUserName(c.user);
    db_.setPassword(c.password);
    QString options = "connect_timeout=5;application_name=sentinel-siem";
    if (!c.sslMode.isEmpty())
        options += ";sslmode=" + c.sslMode;
    if (!c.sslRootCert.isEmpty())
        options += ";sslrootcert=" + c.sslRootCert;
    db_.setConnectOptions(options);
    if (!db_.open()) {
        auto error = db_.lastError().text();
        db_ = QSqlDatabase();
        QSqlDatabase::removeDatabase(connection_);
        throw std::runtime_error(error.toStdString());
    }
    exec("SET TIME ZONE 'UTC'");
    exec("SET statement_timeout = 5000");
    exec("SET lock_timeout = 2000");
    initialize();
}
void Store::initialize() {
    exec("CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,time TEXT NOT NULL,received TEXT NOT "
         "NULL,source TEXT,host TEXT,category TEXT,severity TEXT,message TEXT,ip TEXT,raw TEXT)");
    exec("CREATE INDEX IF NOT EXISTS event_time ON events(time)");
    exec("CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY,event_id INTEGER REFERENCES "
         "events(id),time TEXT,title TEXT,host TEXT,severity TEXT,status TEXT DEFAULT 'open',rule_id "
         "INTEGER,note TEXT DEFAULT '')");
    exec("CREATE INDEX IF NOT EXISTS incident_status_time ON incidents(status,time)");
    exec("CREATE TABLE IF NOT EXISTS assets(host TEXT PRIMARY KEY,ip TEXT,last_seen TEXT,source TEXT)");
    exec("CREATE INDEX IF NOT EXISTS asset_last_seen ON assets(last_seen)");
    exec("CREATE TABLE IF NOT EXISTS rules(id INTEGER PRIMARY KEY,name TEXT,pattern TEXT,threshold "
         "INTEGER,window_seconds INTEGER,severity TEXT,enabled INTEGER DEFAULT 1)");
    exec("CREATE TABLE IF NOT EXISTS matches(rule_id INTEGER,event_id INTEGER REFERENCES events(id),host "
         "TEXT,time TEXT)");
    exec("CREATE INDEX IF NOT EXISTS matches_lookup ON matches(rule_id,host,time)");
    exec("CREATE TABLE IF NOT EXISTS firewall(id INTEGER PRIMARY KEY,name TEXT,direction TEXT,source "
         "TEXT,destination TEXT,protocol TEXT,port INTEGER,action TEXT,enabled INTEGER DEFAULT 1)");
    exec("CREATE TABLE IF NOT EXISTS quarantine(id INTEGER PRIMARY KEY,original TEXT,stored TEXT,sha256 "
         "TEXT,signature TEXT,time TEXT,state TEXT DEFAULT 'isolated')");
    exec("CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,time TEXT,action TEXT,detail TEXT)");
    exec("CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT)");
    exec("CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied TEXT NOT NULL)");
    atomic([&] {
        exec("CREATE TABLE IF NOT EXISTS deliveries(id TEXT PRIMARY KEY, received TEXT NOT NULL)");
        exec("CREATE INDEX IF NOT EXISTS event_received ON events(received)");
        exec("INSERT INTO schema_migrations(version,applied) VALUES(1,?) ON CONFLICT(version) DO NOTHING",
             {QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs)});
    });
    if (!scalar("SELECT value FROM meta WHERE key='initialized'").isValid()) {
        exec("INSERT INTO rules(name,pattern,threshold,window_seconds,severity) VALUES(?,?,?,?,?)",
             {"Подбор пароля", "failed password", 5, 300, "high"});
        exec("INSERT INTO rules(name,pattern,threshold,window_seconds,severity) VALUES(?,?,?,?,?)",
             {"Обнаружено вредоносное ПО", "malware", 1, 60, "critical"});
        exec("INSERT INTO meta VALUES('initialized','1')");
    }
}
Store::~Store() {
    db_.close();
    db_ = QSqlDatabase();
    QSqlDatabase::removeDatabase(connection_);
}
QList<QVariantMap> Store::rows(const QString &sql, const QVariantList &args) const {
    QSqlQuery q(db_);
    if (args.isEmpty()) {
        check(q.exec(sql), q);
    } else {
        check(q.prepare(sql), q);
        for (const auto &v : args)
            q.addBindValue(v);
        check(q.exec(), q);
    }
    QList<QVariantMap> out;
    while (q.next()) {
        QVariantMap row;
        for (int i = 0; i < q.record().count(); ++i)
            row.insert(q.record().fieldName(i), q.value(i));
        out << row;
    }
    return out;
}
QVariant Store::scalar(const QString &sql, const QVariantList &args) const {
    auto r = rows(sql, args);
    return r.isEmpty() ? QVariant() : r.first().first();
}
qint64 Store::exec(const QString &sql, const QVariantList &args) {
    QString statement = sql;
    bool returning = false;
    if (db_.driverName() == "QPSQL") {
        statement.replace("id INTEGER PRIMARY KEY", "id BIGSERIAL PRIMARY KEY");
        statement.replace("event_id INTEGER", "event_id BIGINT").replace("rule_id INTEGER", "rule_id BIGINT");
        returning = QRegularExpression("^INSERT INTO (events|incidents|rules|firewall|quarantine|audit)\\b",
                                       QRegularExpression::CaseInsensitiveOption)
                        .match(statement)
                        .hasMatch();
        if (returning)
            statement += " RETURNING id";
    }
    QSqlQuery q(db_);
    // Qt 6.4's QPSQL uses SQL PREPARE, which cannot prepare SET/DDL.
    // Static statements without parameters execute directly; values remain bound.
    if (args.isEmpty()) {
        check(q.exec(statement), q);
    } else {
        check(q.prepare(statement), q);
        for (const auto &v : args)
            q.addBindValue(v);
        check(q.exec(), q);
    }
    if (returning)
        return q.next() ? q.value(0).toLongLong() : 0;
    // QPSQL::lastInsertId() issues SELECT lastval(), which aborts a transaction
    // if no sequence has been used (for example during schema migrations).
    if (db_.driverName() == "QPSQL")
        return 0;
    return q.lastInsertId().toLongLong();
}
void Store::atomic(const std::function<void()> &operation) {
    if (!db_.transaction())
        throw std::runtime_error(db_.lastError().text().toStdString());
    try {
        operation();
        if (!db_.commit())
            throw std::runtime_error(db_.lastError().text().toStdString());
    } catch (...) {
        db_.rollback();
        throw;
    }
}
int Store::retainEvents(int days, int batchSize) {
    if (days < 1 || batchSize < 1 || batchSize > 10000)
        throw std::runtime_error("Invalid retention bounds");
    const auto cutoff = QDateTime::currentDateTimeUtc().addDays(-days).toString(Qt::ISODateWithMs);
    int removed = 0;
    atomic([&] {
        const auto candidates = rows("SELECT id FROM events WHERE received<? AND id NOT IN "
                                     "(SELECT event_id FROM incidents WHERE event_id IS NOT NULL) "
                                     "ORDER BY id LIMIT ?",
                                     {cutoff, batchSize});
        for (const auto &r : candidates) {
            exec("DELETE FROM matches WHERE event_id=?", {r["id"]});
            exec("DELETE FROM events WHERE id=?", {r["id"]});
        }
        removed = int(candidates.size());
    });
    return removed;
}
qint64 Store::ingest(const Event &e, const QString &deliveryId) {
    const QString now = QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
    const QString stamp =
        (e.time.isValid() ? e.time : QDateTime::currentDateTimeUtc()).toUTC().toString(Qt::ISODateWithMs);
    if (!db_.transaction())
        throw std::runtime_error(db_.lastError().text().toStdString());
    qint64 id = 0;
    try {
        if (!deliveryId.isEmpty() &&
            rows("INSERT INTO deliveries(id,received) VALUES(?,?) ON CONFLICT(id) DO NOTHING RETURNING id",
                 {deliveryId, now})
                .isEmpty()) {
            db_.rollback();
            return 0;
        }
        id = exec("INSERT INTO events(time,received,source,host,category,severity,message,ip,raw) "
                  "VALUES(?,?,?,?,?,?,?,?,?)",
                  {stamp, now, e.source.left(128), e.host.left(256), e.category.left(64), e.severity,
                   e.message.left(16384), e.ip.left(64),
                   QString::fromUtf8(QJsonDocument(e.raw).toJson(QJsonDocument::Compact))});
        if (!e.host.isEmpty())
            exec("INSERT INTO assets(host,ip,last_seen,source) VALUES(?,?,?,?) ON CONFLICT(host) DO UPDATE "
                 "SET ip=CASE WHEN excluded.ip='' THEN assets.ip ELSE excluded.ip "
                 "END,last_seen=excluded.last_seen,source=excluded.source",
                 {e.host.left(256), e.ip.left(64), now, e.source.left(128)});
        bool incident = false;
        for (const auto &r : rows("SELECT * FROM rules WHERE enabled=1")) {
            if (!e.message.contains(r["pattern"].toString(), Qt::CaseInsensitive))
                continue;
            const auto rid = r["id"];
            exec("INSERT INTO matches VALUES(?,?,?,?)", {rid, id, e.host.left(256), now});
            const auto since = QDateTime::currentDateTimeUtc()
                                   .addSecs(-r["window_seconds"].toInt())
                                   .toString(Qt::ISODateWithMs);
            const int count = scalar("SELECT COUNT(*) FROM matches WHERE rule_id=? AND host=? AND time>=?",
                                     {rid, e.host.left(256), since})
                                  .toInt();
            if (count >= r["threshold"].toInt() &&
                !scalar("SELECT COUNT(*) FROM incidents WHERE rule_id=? AND host=? AND time>=?",
                        {rid, e.host.left(256), since})
                     .toInt()) {
                exec("INSERT INTO incidents(event_id,time,title,host,severity,rule_id) VALUES(?,?,?,?,?,?)",
                     {id, now, r["name"], e.host.left(256), r["severity"], rid});
                incident = true;
            }
        }
        if (!incident && (e.severity == "high" || e.severity == "critical") &&
            !scalar("SELECT COUNT(*) FROM incidents WHERE host=? AND title=? AND time>=?",
                    {e.host.left(256), e.message.left(160),
                     QDateTime::currentDateTimeUtc().addSecs(-60).toString(Qt::ISODateWithMs)})
                 .toInt())
            exec("INSERT INTO incidents(event_id,time,title,host,severity) VALUES(?,?,?,?,?)",
                 {id, now, e.message.left(160), e.host.left(256), e.severity});
        exec("DELETE FROM matches WHERE time<?",
             {QDateTime::currentDateTimeUtc().addDays(-1).toString(Qt::ISODateWithMs)});
        if (!db_.commit())
            throw std::runtime_error(db_.lastError().text().toStdString());
    } catch (...) {
        db_.rollback();
        throw;
    }
    emit changed();
    return id;
}
void Store::recordPolicyApplication(const QString &prefix, const QJsonObject &policy, const QString &detail) {
    if (!db_.transaction())
        throw std::runtime_error(db_.lastError().text().toStdString());
    try {
        const auto previous = scalar("SELECT value FROM meta WHERE key=?", {prefix + ".applied"}).toString();
        auto put = [&](const QString &suffix, const QString &value) {
            exec(
                "INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                {prefix + suffix, value});
        };
        if (!previous.isEmpty())
            put(".previous", previous);
        put(".applied", QString::fromUtf8(QJsonDocument(policy).toJson(QJsonDocument::Compact)));
        put(".applied_at", QDateTime::currentDateTimeUtc().toString(Qt::ISODate));
        exec("INSERT INTO audit(time,action,detail) VALUES(?,?,?)",
             {QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs), "ngfw.applied", detail});
        if (!db_.commit())
            throw std::runtime_error(db_.lastError().text().toStdString());
    } catch (...) {
        db_.rollback();
        throw;
    }
    emit changed();
}
bool Store::compareAndSetMeta(const QString &key, const QString &expected, const QString &value) {
    QSqlQuery query(db_);
    if (expected.isEmpty()) {
        check(query.prepare("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO NOTHING"), query);
        query.addBindValue(key);
        query.addBindValue(value);
    } else {
        check(query.prepare("UPDATE meta SET value=? WHERE key=? AND value=?"), query);
        query.addBindValue(value);
        query.addBindValue(key);
        query.addBindValue(expected);
    }
    check(query.exec(), query);
    return query.numRowsAffected() == 1;
}
void Store::audit(const QString &action, const QString &detail) {
    exec("INSERT INTO audit(time,action,detail) VALUES(?,?,?)",
         {QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs), action, detail});
    emit changed();
}
void Store::setIncidentStatus(qint64 id, const QString &status, const QString &note) {
    if (!QStringList{"open", "investigating", "resolved", "false_positive"}.contains(status))
        throw std::runtime_error("Invalid incident state");
    exec("UPDATE incidents SET status=?,note=? WHERE id=?", {status, note, id});
    audit("incident.update", QString("#%1 → %2: %3").arg(id).arg(status, note));
}
void Store::seedDemo() {
    const auto now = QDateTime::currentDateTimeUtc();
    for (int h = 23; h >= 0; --h)
        for (int n = 0; n < (8 + (h * 13) % 29); ++n) {
            Event e;
            e.time = now.addSecs(-h * 3600 - n * 71);
            e.source = (n % 2) ? "Syslog" : "Suricata";
            e.host = QString("ws-office-%1").arg(n % 12 + 1, 2, 10, QChar('0'));
            e.ip = QString("192.168.1.%1").arg(10 + n % 12);
            e.category = "network";
            e.message = "Соединение разрешено политикой";
            ingest(e);
        }
    for (const auto &pair : QList<QPair<QString, QString>>{{"malware · EICAR test signature", "critical"},
                                                           {"SQL injection · HTTP request", "high"},
                                                           {"Подозрительная активность DNS", "medium"},
                                                           {"Пять неудачных попыток входа", "high"}}) {
        Event e;
        e.source = "Демонстрация";
        e.host = "pc-office-01";
        e.ip = "192.168.1.45";
        e.category = "detection";
        e.message = pair.first;
        e.severity = pair.second;
        auto id = ingest(e);
        if (e.severity == "medium")
            exec("INSERT INTO incidents(event_id,time,title,host,severity) VALUES(?,?,?,?,?)",
                 {id, now.toString(Qt::ISODateWithMs), e.message, e.host, e.severity});
    }
    exec("INSERT INTO firewall(name,direction,source,destination,protocol,port,action) VALUES('Ограничить "
         "RDP','input','10.10.0.0/16','any','tcp',3389,'drop')");
    audit("demo.loaded", "Изолированные демонстрационные данные");
}
QString Store::exportJson() const {
    QJsonObject root;
    root["generated_at"] = QDateTime::currentDateTimeUtc().toString(Qt::ISODate);
    root["schema_version"] = 2;
    for (auto name : {"events", "incidents", "assets", "rules", "firewall", "audit"}) {
        QJsonArray a;
        for (const auto &r : rows(QString("SELECT * FROM %1 ORDER BY %2 DESC LIMIT 100000")
                                      .arg(name, QString(name) == "assets" ? "last_seen" : "id")))
            a.append(QJsonObject::fromVariantMap(r));
        root[name] = a;
    }
    QJsonObject policies;
    for (const auto &r : rows("SELECT key,value FROM meta WHERE key LIKE 'ngfw.%'")) {
        const auto json = QJsonDocument::fromJson(r["value"].toString().toUtf8());
        policies[r["key"].toString()] =
            json.isObject() ? QJsonValue(json.object()) : QJsonValue(r["value"].toString());
    }
    root["ngfw_profiles"] = policies;
    root["row_limit_per_table"] = 100000;
    return QString::fromUtf8(QJsonDocument(root).toJson(QJsonDocument::Indented));
}
QString severityLabel(const QString &v) {
    return QMap<QString, QString>{{"info", "Информация"},
                                  {"low", "Низкий"},
                                  {"medium", "Средний"},
                                  {"high", "Высокий"},
                                  {"critical", "Критический"}}
        .value(v, v);
}
QString statusLabel(const QString &v) {
    return QMap<QString, QString>{{"open", "Открыт"},
                                  {"investigating", "Расследование"},
                                  {"resolved", "Решён"},
                                  {"false_positive", "Ложное срабатывание"}}
        .value(v, v);
}
} // namespace siem
