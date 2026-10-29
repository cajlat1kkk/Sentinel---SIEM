#include "queue.h"
#include <QDir>
#include <QFileInfo>
#include <QFile>
#include <QJsonDocument>
#include <QSqlError>
#include <QSqlQuery>

namespace siem::fleet {
Queue::Queue(const QString &path,int maxEvents,qint64 maxBytes)
    : connection_(uuid()),maxEvents_(maxEvents),maxBytes_(maxBytes) {
    require(maxEvents > 0 && maxBytes > 0,"Invalid queue limits");
    require(QDir().mkpath(QFileInfo(path).absolutePath()),"Cannot create spool directory");
    db_ = QSqlDatabase::addDatabase("QSQLITE",connection_); db_.setDatabaseName(path);
    require(db_.open(),db_.lastError().text());
    query("PRAGMA journal_mode=WAL"); query("PRAGMA synchronous=FULL"); query("PRAGMA busy_timeout=5000");
    query("PRAGMA journal_size_limit=4194304");
    query("CREATE TABLE IF NOT EXISTS queue(seq INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT UNIQUE NOT NULL,payload TEXT NOT NULL,bytes INTEGER NOT NULL)");
    query("CREATE TABLE IF NOT EXISTS state(key TEXT PRIMARY KEY,value TEXT NOT NULL)");
    QFile::setPermissions(path,QFile::ReadOwner | QFile::WriteOwner);
}
Queue::~Queue() { db_.close(); db_ = {}; QSqlDatabase::removeDatabase(connection_); }
QSqlQuery Queue::query(const QString &sql,const QVariantList &args) const {
    QSqlQuery q(db_); require(q.prepare(sql),q.lastError().text());
    for (const auto &v : args) q.addBindValue(v);
    require(q.exec(),q.lastError().text()); return q;
}
QString Queue::enqueue(const Event &e) {
    const auto data = QJsonDocument(eventJson(e)).toJson(QJsonDocument::Compact);
    require(data.size() < 16384,"Event exceeds spool record limit");
    require(db_.transaction(),db_.lastError().text());
    try {
        require(count() < maxEvents_ && bytes() + data.size() <= maxBytes_,"Spool full; source paused or UDP event rejected");
        const auto id = uuid();
        query("INSERT INTO queue(id,payload,bytes) VALUES(?,?,?)",{id,QString::fromUtf8(data),data.size()});
        require(db_.commit(),db_.lastError().text()); return id;
    } catch (...) { db_.rollback(); throw; }
}
QJsonArray Queue::batch(int limit) const {
    QJsonArray out;
    auto q = query("SELECT id,payload FROM queue ORDER BY seq LIMIT ?",{qBound(1,limit,BatchSize)});
    while (q.next()) out.append(QJsonObject{{"id",q.value(0).toString()},{"event",QJsonDocument::fromJson(q.value(1).toString().toUtf8()).object()}});
    return out;
}
void Queue::acknowledge(const QJsonArray &ids) {
    require(ids.size() <= BatchSize,"Invalid acknowledgement");
    require(db_.transaction(),db_.lastError().text());
    try {
        for (const auto &id : ids) query("DELETE FROM queue WHERE id=?",{id.toString()});
        require(db_.commit(),db_.lastError().text());
    } catch (...) { db_.rollback(); throw; }
}
int Queue::count() const { auto q = query("SELECT COUNT(*) FROM queue"); q.next(); return q.value(0).toInt(); }
qint64 Queue::bytes() const { auto q = query("SELECT COALESCE(SUM(bytes),0) FROM queue"); q.next(); return q.value(0).toLongLong(); }
QJsonObject Queue::state(const QString &key) const {
    auto q = query("SELECT value FROM state WHERE key=?",{key});
    return q.next() ? QJsonDocument::fromJson(q.value(0).toString().toUtf8()).object() : QJsonObject{};
}
void Queue::setState(const QString &key,const QJsonObject &value) {
    query("INSERT INTO state(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
          {key,QString::fromUtf8(QJsonDocument(value).toJson(QJsonDocument::Compact))});
}
}
