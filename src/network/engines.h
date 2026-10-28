#pragma once
#include "core/store.h"
#include <QProcess>
#include <QTimer>
namespace siem {
class Engines : public QObject {
    Q_OBJECT
  public:
    explicit Engines(Store &store, QObject *parent = nullptr);
    ~Engines() override;
    bool startDpdk(const QStringList &args);
    void stopDpdk();
    void pollVpp(const QString &socket);
    bool dpdkRunning = false, vppConnected = false;
    QString dpdkStatus = "Не запущен", vppStatus = "Не подключён", vppOutput, diagnostics;
    QJsonObject stats;
  signals:
    void changed();

  private:
    Store &store_;
    QProcess dpdk_, vpp_;
    QByteArray buffer_;
    QTimer vppTimeout_;
};
} // namespace siem
