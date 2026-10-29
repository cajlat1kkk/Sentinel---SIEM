#include "fleet/transport.h"
#include <QCommandLineParser>
#include <QCoreApplication>
#include <QJsonDocument>
#include <QTextStream>
using namespace siem::fleet;
int main(int argc,char **argv) {
    QCoreApplication app(argc,argv); app.setApplicationName("siem-fleetctl"); app.setApplicationVersion("0.3.0");
    QCommandLineParser p; p.addHelpOption(); p.addVersionOption();
    p.addOption({"config","Connection configuration JSON","file"});
    p.addOption({"params","Request parameters JSON file (never put secrets in command arguments)","file"});
    p.addOption({"output","Save response to private file","file"});
    p.addOption({"fingerprint","Print certificate fingerprint and exit","certificate"});
    p.addPositionalArgument("method","API method, for example devices.list"); p.process(app);
    try {
        if(p.isSet("fingerprint")) { QTextStream(stdout)<<certificateId(p.value("fingerprint"))<<'\n'; return 0; }
        require(p.positionalArguments().size()==1,"Exactly one API method required");
        RpcClient client(readObject(p.value("config")));
        QTimer::singleShot(0,&client,[&] {
            client.call(p.positionalArguments()[0],p.isSet("params") ? readObject(p.value("params")) : QJsonObject{},
                [&](const QJsonObject &result,const QString &error) {
                if(!error.isEmpty()) { QTextStream(stderr)<<error<<'\n'; app.exit(1); return; }
                auto bytes=QJsonDocument(result).toJson();
                if(p.isSet("output")) { try { writePrivate(p.value("output"),bytes); } catch(const std::exception &e) { QTextStream(stderr)<<e.what()<<'\n'; app.exit(1); return; } }
                else QTextStream(stdout)<<QString::fromUtf8(bytes);
                app.exit(0);
            });
        }); return app.exec();
    } catch(const std::exception &e) { QTextStream(stderr)<<e.what()<<'\n'; return 1; }
}
