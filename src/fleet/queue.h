#pragma once
#include "common.h"
#include <QSqlDatabase>
#include <QSqlQuery>

namespace siem::fleet {
// Local durable spool; all central security data remains in PostgreSQL.
class Queue final {
  public:
    explicit Queue(const QString &path, int maxEvents = 100000, qint64 maxBytes = 256LL*1024*1024);
    ~Queue();
    QString enqueue(const Event &event);
    QJsonArray batch(int limit = BatchSize) const;
    void acknowledge(const QJsonArray &ids);
    int count() const;
    qint64 bytes() const;
    QJsonObject state(const QString &key) const;
    void setState(const QString &key, const QJsonObject &value);
  private:
    QSqlDatabase db_;
    QString connection_;
    int maxEvents_;
    qint64 maxBytes_;
    QSqlQuery query(const QString &sql, const QVariantList &args = {}) const;
};
}
