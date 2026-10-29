#include "transport.h"
#include <QJsonDocument>
#include <QPointer>

namespace siem::fleet {
RpcClient::RpcClient(const QJsonObject &c, QObject *p) : QObject(p), config_(c), tls_(tlsConfiguration(c)) {
    require(!c["host"].toString().isEmpty() && c["port"].toInt() > 0 && c["port"].toInt() <= 65535, "Invalid server address");
}
void RpcClient::call(const QString &method, const QJsonObject &params, Callback callback) {
    if (busy_) { callback({}, "Request already in progress"); return; }
    const auto frame = QJsonDocument(QJsonObject{{"method",method},{"params",params}}).toJson(QJsonDocument::Compact) + '\n';
    if (frame.size() > MaxFrame) { callback({}, "Request too large"); return; }
    busy_ = true;
    auto *socket = new QSslSocket(this);
    auto *timer = new QTimer(socket);
    timer->setSingleShot(true);
    auto finished = std::make_shared<bool>(false);
    auto buffer = std::make_shared<QByteArray>();
    auto done = [this,socket,finished,callback](const QJsonObject &result, const QString &error) {
        if (*finished) return;
        *finished = true; busy_ = false; socket->abort(); socket->deleteLater(); callback(result,error);
    };
    socket->setSslConfiguration(tls_);
    socket->setReadBufferSize(MaxFrame + 1);
    connect(timer, &QTimer::timeout, socket, [done] { done({}, "Server timeout"); });
    connect(socket, &QSslSocket::sslErrors, socket, [done](const QList<QSslError> &errors) {
        done({}, "TLS verification failed: " + (errors.isEmpty() ? QString() : errors.first().errorString()));
    });
    connect(socket, &QSslSocket::errorOccurred, socket, [socket,done] { done({},socket->errorString()); });
    connect(socket, &QSslSocket::encrypted, socket, [socket,frame] { socket->write(frame); });
    connect(socket, &QSslSocket::readyRead, socket, [socket,buffer,done] {
        buffer->append(socket->readAll());
        if (buffer->size() > MaxFrame) { done({},"Response too large"); return; }
        if (!buffer->contains('\n')) return;
        QJsonParseError error;
        auto doc = QJsonDocument::fromJson(*buffer, &error);
        if (error.error != QJsonParseError::NoError || !doc.isObject() || !doc.object()["ok"].isBool()) {
            done({},"Invalid server response"); return;
        }
        auto r = doc.object();
        done(r["result"].toObject(),r["ok"].toBool() ? QString() : r["error"].toString("Request failed"));
    });
    connect(socket, &QSslSocket::disconnected, socket, [done] { done({},"Server disconnected"); });
    timer->start(15000);
    socket->connectToHostEncrypted(config_["host"].toString(), quint16(config_["port"].toInt()));
}
RpcServer::RpcServer(const QSslConfiguration &tls, Handler h, QObject *p)
    : QTcpServer(p), tls_(tls), handler_(std::move(h)) {}
void RpcServer::incomingConnection(qintptr fd) {
    auto *socket = new QSslSocket(this);
    if (!socket->setSocketDescriptor(fd)) { socket->deleteLater(); return; }
    if (connections_ >= 64) { socket->abort(); socket->deleteLater(); return; }
    ++connections_;
    connect(socket,&QObject::destroyed,this,[this] { --connections_; });
    socket->setSslConfiguration(tls_);
    socket->setReadBufferSize(MaxFrame + 1);
    auto *timer = new QTimer(socket); timer->setSingleShot(true); timer->start(20000);
    connect(timer,&QTimer::timeout,socket,[socket] { socket->abort(); socket->deleteLater(); });
    connect(socket,&QSslSocket::disconnected,socket,&QObject::deleteLater);
    connect(socket,&QSslSocket::errorOccurred,socket,[socket] { socket->abort(); socket->deleteLater(); });
    connect(socket,&QSslSocket::sslErrors,socket,[socket] { socket->abort(); socket->deleteLater(); });
    auto buffer = std::make_shared<QByteArray>();
    auto dispatched = std::make_shared<bool>(false);
    connect(socket,&QSslSocket::readyRead,socket,[this,socket,buffer,dispatched] {
        if (!socket->isEncrypted()) { socket->abort(); return; }
        buffer->append(socket->readAll());
        if (*dispatched || buffer->size() > MaxFrame) { socket->abort(); return; }
        if (!buffer->contains('\n')) return;
        *dispatched = true;
        QJsonParseError parse;
        const auto doc = QJsonDocument::fromJson(*buffer,&parse);
        if (parse.error != QJsonParseError::NoError || !doc.isObject() || socket->peerCertificate().isNull()) {
            socket->abort(); return;
        }
        const auto request = doc.object();
        const QString identity = digest(socket->peerCertificate().toDer());
        QPointer<QSslSocket> guard(socket);
        handler_(identity,request["method"].toString(),request["params"].toObject(),
                 [guard](const QJsonObject &result,const QString &error) {
            if (!guard) return;
            auto data = QJsonDocument(QJsonObject{{"ok",error.isEmpty()},{"result",result},{"error",error}}).toJson(QJsonDocument::Compact) + '\n';
            if (data.size() > MaxFrame) data = "{\"ok\":false,\"error\":\"Response too large; narrow query\"}\n";
            guard->write(data); guard->disconnectFromHost();
        });
    });
    socket->startServerEncryption();
}
}
