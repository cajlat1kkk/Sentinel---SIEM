#include "fleet/agent.h"
#include "fleet/service.h"
#include <QCommandLineParser>
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QLockFile>
#include <QTextStream>
using namespace siem::fleet;
int main(int argc, char **argv) {
    return runService(argc, argv, "SentinelAgent", [&] {
        QCoreApplication app(argc, argv);
        app.setApplicationName("siem-agent");
        app.setApplicationVersion("0.3.0");
        QCommandLineParser p;
        p.addHelpOption();
        p.addVersionOption();
        p.addOption({"config", "Agent configuration JSON", "file"});
        p.addOption({"service", "Run as Windows service"});
        p.addOption({"check-config", "Validate configuration and TLS, then exit"});
        p.addOption({"watchdog", "Internal firewall rollback watchdog", "policy-token"});
        p.process(app);
        try {
            auto c = readObject(p.value("config"));
            const auto dir = c["state_dir"].toString();
            require(QDir::isAbsolutePath(dir) && QDir::cleanPath(dir) != QDir::rootPath(),
                    "An absolute private state_dir is required");
            require(QDir().mkpath(dir), "Cannot create agent state directory");
            require(QFile::setPermissions(dir, QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner),
                    "Cannot protect agent state directory");
            tlsConfiguration(c["server"].toObject());
            if (p.isSet("check-config")) {
                QTextStream(stdout) << "Agent TLS configuration valid\n";
                return 0;
            }
            if (p.isSet("watchdog"))
                return PolicyController::watchdog(c, p.value("watchdog"));
            QLockFile lock(dir + "/agent.lock");
            require(lock.tryLock(0), "Another agent already uses this state directory");
            Agent agent(c, QFileInfo(p.value("config")).absoluteFilePath());
            installStopHandlers();
            agent.start();
            serviceReady();
            return app.exec();
        } catch (const std::exception &e) {
            QTextStream(stderr) << e.what() << '\n';
            return 1;
        }
    });
}
