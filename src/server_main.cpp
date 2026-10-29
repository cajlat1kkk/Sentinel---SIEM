#include "fleet/repository.h"
#include "fleet/service.h"
#include "fleet/transport.h"
#include <QCommandLineParser>
#include <QCoreApplication>
#include <QJsonDocument>
#include <QPointer>
#include <QTextStream>
#include <QThread>

using namespace siem;
using namespace siem::fleet;
int main(int argc,char **argv) {
    return runService(argc,argv,"SentinelServer",[&] {
        QCoreApplication app(argc,argv); app.setApplicationName("siem-server"); app.setApplicationVersion("0.3.0");
        QCommandLineParser parser; parser.addHelpOption(); parser.addVersionOption();
        parser.addOption({"config","Server configuration JSON","file"});
        parser.addOption({"service","Run under Windows Service Control Manager"});
        parser.addOption({"check-config","Validate TLS and PostgreSQL, then exit"});
        parser.addOption({"add-operator","Provision operator certificate (local administration)","certificate"});
        parser.addOption({"name","Operator name","name"});
        parser.addOption({"role","admin or analyst","role","analyst"});
        parser.addOption({"ready-file","Write bound port after startup","path"});
        parser.process(app);
        QThread databaseThread;
        QObject worker; worker.moveToThread(&databaseThread);
        std::unique_ptr<Store> store;
        std::unique_ptr<Repository> repository;
        int result=1;
        try {
            auto config=readObject(parser.value("config"));
            auto tls=tlsConfiguration(config);
            const auto db=databaseConfig(config["database"].toObject());
            QString initError;
            databaseThread.start();
            QMetaObject::invokeMethod(&worker,[&] {
                try { store=std::make_unique<Store>(db); repository=std::make_unique<Repository>(*store); }
                catch(const std::exception &e) { initError=QString::fromUtf8(e.what()); }
            },Qt::BlockingQueuedConnection);
            require(initError.isEmpty(),initError);
            if(parser.isSet("add-operator")) {
                const auto fingerprint=certificateId(parser.value("add-operator"));
                QMetaObject::invokeMethod(&worker,[&] {
                    try { repository->addOperator(fingerprint,parser.value("name"),parser.value("role")); }
                    catch(const std::exception &e) { initError=QString::fromUtf8(e.what()); }
                },Qt::BlockingQueuedConnection);
                require(initError.isEmpty(),initError);
                QTextStream(stdout)<<"Operator provisioned: "<<fingerprint<<'\n'; result=0;
            } else if(parser.isSet("check-config")) { QTextStream(stdout)<<"TLS and PostgreSQL ready\n"; result=0; }
            else {
                int pending=0;
                RpcServer server(tls,[&](const QString &identity,const QString &method,const QJsonObject &params,RpcServer::Reply reply) {
                    if(pending>=128) { reply({},"Server busy; retry"); return; }
                    ++pending;
                    QPointer<QObject> alive(&app);
                    QMetaObject::invokeMethod(&worker,[&,identity,method,params,reply,alive] {
                        QJsonObject response; QString error;
                        try { response=repository->dispatch(identity,method,params); }
                        catch(const std::exception &e) { error=QString::fromUtf8(e.what()); }
                        if(alive) QMetaObject::invokeMethod(alive,[&,response,error,reply] { --pending; reply(response,error); },Qt::QueuedConnection);
                    },Qt::QueuedConnection);
                });
                const auto address=QHostAddress(config["listen"].toString("127.0.0.1"));
                const int port=config["port"].toInt(7443);
                require(!address.isNull() && port>=0 && port<=65535,"Invalid listen address");
                require(server.listen(address,quint16(port)),server.errorString());
                if(parser.isSet("ready-file")) writePrivate(parser.value("ready-file"),QByteArray::number(server.serverPort()));
                QTextStream(stdout)<<"Sentinel server listening on "<<server.serverAddress().toString()<<':'<<server.serverPort()<<" (mutual TLS)\n";
                QTimer retention;
                const int retentionDays=config["retention_days"].toInt(90);
                require(retentionDays>=1 && retentionDays<=36500,"Invalid event retention period");
                QObject::connect(&retention,&QTimer::timeout,&worker,[&] {
                    try { store->retainEvents(retentionDays); }
                    catch(const std::exception &e) { qWarning("Retention failed: %s",e.what()); }
                });
                retention.start(60000);
                installStopHandlers(); serviceReady(); result=app.exec(); server.close();
            }
        } catch(const std::exception &e) { QTextStream(stderr)<<e.what()<<'\n'; }
        if(databaseThread.isRunning()) {
            QMetaObject::invokeMethod(&worker,[&] { repository.reset(); store.reset(); worker.moveToThread(app.thread()); },Qt::BlockingQueuedConnection);
            databaseThread.quit(); databaseThread.wait();
        }
        return result;
    });
}
