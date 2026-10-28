#pragma once
#include "store.h"
#include <QUdpSocket>
namespace siem {
class Collector : public QObject {
    Q_OBJECT
  public:
    explicit Collector(Store &store, QObject *parent = nullptr);
    bool start(quint16 port, QString *error);
    void stop();
    bool active() const {
        return socket_.state() == QAbstractSocket::BoundState;
    }
    quint16 port() const {
        return socket_.localPort();
    }
    static Event parse(const QByteArray &data, const QString &sender = "local",
                       const QString &source = "Syslog");
    int importFile(const QString &path, QString *error);
  signals:
    void error(const QString &message);

  private:
    Store &store_;
    QUdpSocket socket_;
    void drain();
};
} // namespace siem
