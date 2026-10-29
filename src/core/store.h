#pragma once
#include <QDateTime>
#include <QJsonObject>
#include <QObject>
#include <QSqlDatabase>
#include <QVariantMap>
#include <functional>

namespace siem {
struct DatabaseConfig {
    QString host = "127.0.0.1", name = "sentinel", user = "sentinel", password;
    int port = 5432;
};
struct Event {
    QDateTime time = QDateTime::currentDateTimeUtc();
    QString source, host, category = "system", severity = "info", message, ip;
    QJsonObject raw;
};
class Store : public QObject {
    Q_OBJECT
  public:
    explicit Store(const QString &path, QObject *parent = nullptr);
    explicit Store(const DatabaseConfig &config, QObject *parent = nullptr);
    ~Store() override;
    QList<QVariantMap> rows(const QString &sql, const QVariantList &args = {}) const;
    QVariant scalar(const QString &sql, const QVariantList &args = {}) const;
    qint64 exec(const QString &sql, const QVariantList &args = {});
    qint64 ingest(const Event &event, const QString &deliveryId = {});
    void atomic(const std::function<void()> &operation);
    int retainEvents(int days, int batchSize = 1000);
    void recordPolicyApplication(const QString &keyPrefix, const QJsonObject &policy, const QString &detail);
    bool compareAndSetMeta(const QString &key, const QString &expected, const QString &value);
    void audit(const QString &action, const QString &detail);
    void setIncidentStatus(qint64 id, const QString &status, const QString &note);
    void seedDemo();
    QString path() const {
        return path_;
    }
    QString exportJson() const;
  signals:
    void changed();

  private:
    QSqlDatabase db_;
    QString connection_, path_;
    void initialize();
};
QString severityLabel(const QString &value);
QString statusLabel(const QString &value);
} // namespace siem
