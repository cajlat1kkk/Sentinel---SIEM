#pragma once
#include "core/scanner.h"
#include "policy.h"
#include "queue.h"
#include "transport.h"
#include <QProcess>
#include <QUdpSocket>

namespace siem::fleet {
class Agent final : public QObject {
    Q_OBJECT
  public:
    Agent(const QJsonObject &config, const QString &configPath, QObject *parent = nullptr);
    ~Agent() override;
    void start();

  private:
    QJsonObject config_;
    Queue queue_;
    RpcClient client_;
    PolicyController policy_;
    Scanner scanner_;
    QUdpSocket syslog_;
    QProcess journal_;
    QTimer poll_, sources_, schedule_;
    QByteArray journalBuffer_;
    QString sourceError_, connectionError_, scanCommand_;
    QStringList scanPaths_;
    QJsonObject scanSummary_;
    int failures_ = 0;
    qint64 rejected_ = 0;
    bool enrolled_ = false;
    void synchronize();
    void sourceTick();
    void startJournal();
    void windowsEvents();
    bool enqueue(Event event);
    QJsonObject health() const;
    void scan(const QString &command = {});
    void scanNext();
    void commandResult(const QString &id, const QJsonObject &result);
};
} // namespace siem::fleet
