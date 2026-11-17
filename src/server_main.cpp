#include "fleet/metrics.h"
#include "fleet/repository.h"
#include "fleet/service.h"
#include "fleet/transport.h"
#include "network/radar.h"
#include <QCommandLineParser>
#include <QCoreApplication>
#include <QJsonDocument>
#include <QPointer>
#include <QTextStream>
#include <QThread>

using namespace siem;
using namespace siem::fleet;
int main(int argc, char **argv) {
    return runService(argc, argv, "SentinelServer", [&] {
        QCoreApplication app(argc, argv);
        app.setApplicationName("siem-server");
        app.setApplicationVersion("0.3.0");
        QCommandLineParser parser;
        parser.addHelpOption();
        parser.addVersionOption();
        parser.addOption({"config", "Server configuration JSON", "file"});
        parser.addOption({"service", "Run under Windows Service Control Manager"});
        parser.addOption({"check-config", "Validate TLS and PostgreSQL, then exit"});
        parser.addOption(
            {"add-operator", "Provision operator certificate (local administration)", "certificate"});
        parser.addOption({"name", "Operator name", "name"});
        parser.addOption({"role", "admin or analyst", "role", "analyst"});
        parser.addOption({"ready-file", "Write bound port after startup", "path"});
        parser.process(app);
        QThread databaseThread;
        QObject worker;
        worker.moveToThread(&databaseThread);
        std::unique_ptr<Store> store;
        std::unique_ptr<Repository> repository;
        MetricsRegistry metrics;
        std::unique_ptr<PrometheusServer> metricsServer;
        int result = 1;
        try {
            auto config = readObject(parser.value("config"));
            require(!config.contains("radar") || config["radar"].isObject(), "radar must be an object");
            NetworkRadar radar(config["radar"].toObject());
            const auto metricsConfiguration = config["metrics"].toObject();
            const auto metricsConfigurationError = prometheusConfigurationError(metricsConfiguration);
            require(metricsConfigurationError.isEmpty(), metricsConfigurationError);
            auto tls = tlsConfiguration(config);
            const auto db = databaseConfig(config["database"].toObject());
            QString initError;
            databaseThread.start();
            QMetaObject::invokeMethod(
                &worker,
                [&] {
                    try {
                        store = std::make_unique<Store>(db);
                        repository = std::make_unique<Repository>(*store);
                    } catch (const std::exception &e) {
                        initError = QString::fromUtf8(e.what());
                    }
                },
                Qt::BlockingQueuedConnection);
            require(initError.isEmpty(), initError);
            if (parser.isSet("add-operator")) {
                const auto fingerprint = certificateId(parser.value("add-operator"));
                QMetaObject::invokeMethod(
                    &worker,
                    [&] {
                        try {
                            repository->addOperator(fingerprint, parser.value("name"), parser.value("role"));
                        } catch (const std::exception &e) {
                            initError = QString::fromUtf8(e.what());
                        }
                    },
                    Qt::BlockingQueuedConnection);
                require(initError.isEmpty(), initError);
                QTextStream(stdout) << "Operator provisioned: " << fingerprint << '\n';
                result = 0;
            } else if (parser.isSet("check-config")) {
                QTextStream(stdout) << "TLS and PostgreSQL ready\n";
                result = 0;
            } else {
                int pending = 0;
                radar.start();
                bool radarPending = false;
                QTimer radarFlush;
                QObject::connect(&radarFlush, &QTimer::timeout, &app, [&] {
                    metrics.setRadarSnapshot(radar.status());
                    if (radarPending || pending >= 64) return;
                    const auto flows = radar.takeFlows(), alerts = radar.takeAlerts();
                    if (flows.isEmpty() && alerts.isEmpty()) return;
                    radarPending = true;
                    QMetaObject::invokeMethod(&worker, [&, flows, alerts] {
                        bool success = false;
                        try {
                            if (!store) { store = std::make_unique<Store>(db); repository = std::make_unique<Repository>(*store); }
                            repository->ingestRadar(flows, alerts);
                            success = true;
                        } catch (const std::exception &e) {
                            qWarning("Radar persistence failed: %s", e.what());
                            repository.reset(); store.reset();
                        }
                        QMetaObject::invokeMethod(&app, [&, success, count = flows.size() + alerts.size()] {
                            radarPending = false;
                            radar.persistenceResult(success, count);
                            metrics.setRadarSnapshot(radar.status());
                        }, Qt::QueuedConnection);
                    }, Qt::QueuedConnection);
                });
                radarFlush.start(5000);
                RpcServer server(tls, [&](const QString &identity, const QString &method,
                                          const QJsonObject &params, RpcServer::Reply reply) {
                    metrics.recordRpcRequest();
                    if (pending >= 128) {
                        metrics.recordRpcResult(true);
                        reply({}, "Server busy; retry");
                        return;
                    }
                    ++pending;
                    metrics.setRpcPending(pending);
                    QPointer<QObject> alive(&app);
                    const auto radarStatus = radar.status();
                    QMetaObject::invokeMethod(
                        &worker,
                        [&, identity, method, params, reply, alive, radarStatus] {
                            QJsonObject response;
                            QString error;
                            try {
                                if (!store) {
                                    store = std::make_unique<Store>(db);
                                    repository = std::make_unique<Repository>(*store);
                                }
                                store->scalar("SELECT 1");
                                response = repository->dispatch(identity, method, params);
                                if (method == "radar.flows" || method == "radar.top") response["status"] = radarStatus;
                            } catch (const std::exception &e) {
                                error = QString::fromUtf8(e.what());
                                // Retry the connection on the next request. Committed delivery IDs make
                                // retries safe.
                                repository.reset();
                                store.reset();
                            }
                            if (alive)
                                QMetaObject::invokeMethod(
                                    alive,
                                    [&, response, error, reply] {
                                        --pending;
                                        metrics.setRpcPending(pending);
                                        metrics.recordRpcResult(!error.isEmpty());
                                        reply(response, error);
                                    },
                                    Qt::QueuedConnection);
                        },
                        Qt::QueuedConnection);
                });
                const auto address = QHostAddress(config["listen"].toString("127.0.0.1"));
                const int port = config["port"].toInt(7443);
                require(!address.isNull() && port >= 0 && port <= 65535, "Invalid listen address");
                require(server.listen(address, quint16(port)), server.errorString());
                if (metricsConfiguration["enabled"].toBool(false)) {
                    metricsServer = std::make_unique<PrometheusServer>(metrics);
                    QString metricsError;
                    require(metricsServer->listenConfigured(metricsConfiguration, &metricsError),
                            metricsError);
                }
                if (parser.isSet("ready-file"))
                    writePrivate(parser.value("ready-file"), QByteArray::number(server.serverPort()));
                QTextStream(stdout) << "Sentinel server listening on " << server.serverAddress().toString()
                                    << ':' << server.serverPort() << " (mutual TLS)\n";
                if (metricsServer)
                    QTextStream(stdout)
                        << "Prometheus metrics listening on " << metricsServer->serverAddress().toString()
                        << ':' << metricsServer->serverPort() << " (HTTP, local by default)\n";
                bool metricsRefreshPending = false;
                auto refreshMetrics = [&] {
                    if (!metricsServer || metricsRefreshPending)
                        return;
                    metricsRefreshPending = true;
                    QPointer<QObject> alive(&app);
                    QMetaObject::invokeMethod(
                        &worker,
                        [&, alive] {
                            QJsonObject snapshot;
                            QString error;
                            try {
                                if (!store) {
                                    store = std::make_unique<Store>(db);
                                    repository = std::make_unique<Repository>(*store);
                                }
                                store->scalar("SELECT 1");
                                snapshot = repository->monitoringSnapshot();
                            } catch (const std::exception &e) {
                                error = QString::fromUtf8(e.what());
                                repository.reset();
                                store.reset();
                            }
                            if (alive)
                                QMetaObject::invokeMethod(
                                    alive,
                                    [&, snapshot, error] {
                                        metricsRefreshPending = false;
                                        if (error.isEmpty())
                                            metrics.setDatabaseSnapshot(snapshot);
                                        else
                                            metrics.setDatabaseDown();
                                    },
                                    Qt::QueuedConnection);
                        },
                        Qt::QueuedConnection);
                };
                QTimer metricsRefresh;
                QObject::connect(&metricsRefresh, &QTimer::timeout, &app, refreshMetrics);
                if (metricsServer) {
                    metricsRefresh.start(15000);
                    refreshMetrics();
                }
                QTimer retention;
                const int retentionDays = config["retention_days"].toInt(90);
                require(retentionDays >= 1 && retentionDays <= 36500, "Invalid event retention period");
                QObject::connect(&retention, &QTimer::timeout, &worker, [&, retentionDays] {
                    try {
                        if (store) {
                            store->retainEvents(retentionDays);
                            repository->retainRadar();
                        }
                    } catch (const std::exception &e) {
                        qWarning("Retention failed: %s", e.what());
                    }
                });
                retention.start(60000);
                installStopHandlers();
                serviceReady();
                result = app.exec();
                server.close();
                radarFlush.stop();
                // Finish queued database work while its captured config is still alive.
                QMetaObject::invokeMethod(&worker, [] {}, Qt::BlockingQueuedConnection);
            }
        } catch (const std::exception &e) {
            QTextStream(stderr) << e.what() << '\n';
        }
        if (databaseThread.isRunning()) {
            QMetaObject::invokeMethod(
                &worker,
                [&] {
                    repository.reset();
                    store.reset();
                    worker.moveToThread(app.thread());
                },
                Qt::BlockingQueuedConnection);
            databaseThread.quit();
            databaseThread.wait();
        }
        return result;
    });
}
