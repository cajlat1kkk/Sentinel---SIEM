#pragma once
#include "core/store.h"
#include <QJsonObject>
#include <QProcess>
#include <QStringList>
#include <QTimer>

namespace siem {
class Engines : public QObject {
    Q_OBJECT
  public:
    struct PciPort {
        QString bdf;
        QString driver;
        bool iommu = false;
    };

    explicit Engines(Store &store, QObject *parent = nullptr);
    ~Engines() override;
    bool startDpdk(const QStringList &args);
    void stopDpdk();
    void pollVpp(const QString &socket);
    void startVppMonitoring(const QString &socket, int intervalMs = 15000);
    void stopVppMonitoring();
    void setStatus(const QString &text);
    QString suggestedEalArgs() const;
    bool portUsedByVpp(const QStringList &args, QString *bdf = nullptr) const;
    QStringList vppPorts() const {
        return vppPorts_;
    }
    bool busy() const {
        return dpdk_.state() != QProcess::NotRunning;
    }
    bool vppPolling() const {
        return vpp_.state() != QProcess::NotRunning;
    }

    static QList<PciPort> discoverPorts(const QString &sysfs = QStringLiteral("/sys/bus/pci/devices"));
    static QJsonObject parseVppInterfaces(const QString &output);
    static QStringList pciAddresses(const QString &text);
    static QStringList vppPciAddresses(const QString &output);

    bool dpdkRunning = false, vppConnected = false;
    QString dpdkStatus = "Не запущен", vppStatus = "Не подключён", vppOutput, diagnostics,
            dpdkSource = "live";
    QJsonObject stats;
  signals:
    void changed();

  private:
    Store &store_;
    QProcess dpdk_, vpp_;
    QByteArray buffer_;
    QTimer vppTimeout_, vppRefresh_;
    QString vppSocket_ = "/run/vpp/cli.sock";
    QStringList vppPorts_;
};
} // namespace siem
