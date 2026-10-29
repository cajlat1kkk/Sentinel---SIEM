#pragma once
#include "common.h"
#include <QSslSocket>
#include <QTcpServer>
#include <QTimer>
#include <functional>

namespace siem::fleet {
class RpcClient final : public QObject {
    Q_OBJECT
  public:
    using Callback = std::function<void(const QJsonObject &, const QString &)>;
    RpcClient(const QJsonObject &configuration, QObject *parent = nullptr);
    void call(const QString &method, const QJsonObject &params, Callback callback);
    bool busy() const { return busy_; }
  private:
    QJsonObject config_;
    QSslConfiguration tls_;
    bool busy_ = false;
};
class RpcServer final : public QTcpServer {
    Q_OBJECT
  public:
    using Reply = std::function<void(const QJsonObject &, const QString &)>;
    using Handler = std::function<void(const QString &, const QString &, const QJsonObject &, Reply)>;
    RpcServer(const QSslConfiguration &tls, Handler handler, QObject *parent = nullptr);
  protected:
    void incomingConnection(qintptr descriptor) override;
  private:
    QSslConfiguration tls_;
    Handler handler_;
    int connections_ = 0;
};
}
