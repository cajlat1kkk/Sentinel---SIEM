#pragma once
#include "common.h"
#include <QObject>
#include <QProcess>
#include <QTimer>

namespace siem::fleet {
class PolicyController final : public QObject {
    Q_OBJECT
  public:
    PolicyController(const QJsonObject &config, const QString &configPath, QObject *parent = nullptr);
    ~PolicyController() override;
    void recover();
    void accept(const QJsonObject &desired, const QString &confirmation);
    QJsonObject health() const;
    QJsonObject activePolicy() const;
    static int watchdog(const QJsonObject &config, const QString &expectedToken);
  signals:
    void changed();

  private:
    QJsonObject config_;
    QString configPath_, statePath_, directory_;
    QProcess process_;
    QTimer timeout_;
    QJsonObject state() const;
    void save(const QJsonObject &value) const;
    void apply(const QJsonObject &desired);
    static QString firewallHelper();
    static bool applyBlocking(const QJsonObject &policy, const QString &directory, QString *error);
    static void rollback(const QJsonObject &config, const QString &token);
};
} // namespace siem::fleet
