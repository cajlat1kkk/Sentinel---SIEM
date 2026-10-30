#include "core/scanner.h"
#include "fleet/policy.h"
#include "fleet/queue.h"
#include "fleet/repository.h"
#include <QFile>
#include <QJsonDocument>
#include <QProcess>
#include <QTemporaryDir>
#include <QtTest>
using namespace siem;
using namespace siem::fleet;
class FleetTests final : public QObject {
    Q_OBJECT
  private slots:
    void queueSurvivesRestartAndBackpressure() {
        QTemporaryDir dir;
        QString id;
        {
            Queue queue(dir.filePath("queue.sqlite"), 2, 1024 * 1024);
            Event e;
            e.message = "queued offline";
            id = queue.enqueue(e);
            queue.enqueue(e);
            QCOMPARE(queue.count(), 2);
            QVERIFY_EXCEPTION_THROWN(queue.enqueue(e), std::runtime_error);
        }
        {
            Queue queue(dir.filePath("queue.sqlite"), 2);
            QCOMPARE(queue.count(), 2);
            QCOMPARE(queue.batch()[0].toObject()["id"].toString(), id);
            queue.acknowledge({id});
            QCOMPARE(queue.count(), 1);
            queue.acknowledge({id});
            QCOMPARE(queue.count(), 1);
        }
    }
    void enrollmentAuthorizationReplayAndRevocation() {
        QTemporaryDir dir;
        Store store(dir.filePath("server.sqlite"));
        Repository repo(store);
        const QString admin(64, 'a'), analyst(64, 'b'), device(64, 'c'), other(64, 'd');
        repo.addOperator(admin, "Administrator", "admin");
        repo.addOperator(analyst, "Analyst", "analyst");
        QVERIFY_EXCEPTION_THROWN(repo.dispatch(analyst, "enrollment.create", {{"identity", device}}),
                                 std::runtime_error);
        auto ticket = repo.dispatch(admin, "enrollment.create", {{"identity", device}});
        auto params = QJsonObject{{"token", ticket["token"]}, {"hostname", "test-pc"}, {"platform", "linux"}};
        QVERIFY_EXCEPTION_THROWN(repo.dispatch(other, "agent.enroll", params), std::runtime_error);
        QVERIFY(repo.dispatch(device, "agent.enroll", params)["enrolled"].toBool());
        QVERIFY(repo.dispatch(device, "agent.enroll", params)["enrolled"].toBool());
        QVERIFY_EXCEPTION_THROWN(repo.dispatch(device, "events.list", {}), std::runtime_error);
        const auto eventId = uuid();
        Event event;
        event.message = "malware detected in test";
        event.severity = "high";
        event.host = "spoofed-host";
        auto batch = QJsonArray{QJsonObject{{"id", eventId}, {"event", eventJson(event)}}};
        auto response = repo.dispatch(device, "agent.poll", {{"events", batch}});
        QCOMPARE(response["ack"].toArray().size(), 1);
        repo.dispatch(device, "agent.poll", {{"events", batch}});
        QCOMPARE(store.scalar("SELECT COUNT(*) FROM events").toInt(), 1);
        QCOMPARE(store.scalar("SELECT host FROM events").toString(), QString("test-pc"));
        QVERIFY(repo.dispatch(analyst, "events.list", {})["rows"].toArray().size() == 1);
        repo.dispatch(admin, "devices.revoke", {{"identity", device}});
        QVERIFY_EXCEPTION_THROWN(repo.dispatch(device, "agent.poll", {}), std::runtime_error);
        QVERIFY_EXCEPTION_THROWN(repo.dispatch(device, "agent.enroll", params), std::runtime_error);
    }
    void policyRevisionAndAuditAreAtomic() {
        QTemporaryDir dir;
        Store store(dir.filePath("server.sqlite"));
        Repository repo(store);
        const QString admin(64, 'a');
        repo.addOperator(admin, "Admin", "admin");
        auto request =
            QJsonObject{{"group", "default"}, {"expected_revision", 0}, {"policy", defaultEndpointPolicy()}};
        QCOMPARE(repo.dispatch(admin, "policies.set", request)["revision"].toInt(), 1);
        QVERIFY_EXCEPTION_THROWN(repo.dispatch(admin, "policies.set", request), std::runtime_error);
        store.exec("CREATE TRIGGER reject_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'test audit "
                   "failure'); END");
        request["expected_revision"] = 1;
        QVERIFY_EXCEPTION_THROWN(repo.dispatch(admin, "policies.set", request), std::runtime_error);
        QCOMPARE(repo.dispatch(admin, "policies.get", {{"group", "default"}})["revision"].toInt(), 1);
    }
    void deliveryReceiptRollsBackWithEvent() {
        QTemporaryDir dir;
        Store store(dir.filePath("server.sqlite"));
        store.exec("CREATE TRIGGER reject_event BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'test event "
                   "failure'); END");
        Event e;
        e.message = "retry me";
        QVERIFY_EXCEPTION_THROWN(store.ingest(e, "delivery-1"), std::runtime_error);
        QCOMPARE(store.scalar("SELECT COUNT(*) FROM deliveries").toInt(), 0);
        store.exec("DROP TRIGGER reject_event");
        QVERIFY(store.ingest(e, "delivery-1") > 0);
        QCOMPARE(store.ingest(e, "delivery-1"), qint64(0));
        QCOMPARE(store.scalar("SELECT COUNT(*) FROM events").toInt(), 1);
    }
    void retentionPreservesIncidentEvidence() {
        QTemporaryDir dir;
        Store store(dir.filePath("server.sqlite"));
        Event normal;
        normal.message = "normal";
        store.ingest(normal);
        Event finding;
        finding.message = "malware";
        finding.severity = "critical";
        finding.host = "host";
        store.ingest(finding);
        store.exec("UPDATE events SET received='2000-01-01T00:00:00.000Z'");
        QCOMPARE(store.retainEvents(90), 1);
        QCOMPARE(store.scalar("SELECT COUNT(*) FROM events").toInt(), 1);
        QCOMPARE(store.scalar("SELECT message FROM events").toString(), QString("malware"));
    }
    void scheduledScanExclusions() {
        QTemporaryDir dir;
        QFile f(dir.filePath("sample.txt"));
        QVERIFY(f.open(QIODevice::WriteOnly));
        f.write("sample");
        f.close();
        std::atomic_bool cancel{false};
        QMap<QString, QString> hashes{{Scanner::hashFile(f.fileName()), "test signature"}};
        QCOMPARE(Scanner::scan(dir.path(), hashes, cancel, false).findings.size(), 1);
        QCOMPARE(Scanner::scan(dir.path(), hashes, cancel, false, {f.fileName()}).findings.size(), 0);
    }
    void firewallWatchdog() {
        if (!qEnvironmentVariableIsSet("SIEM_TEST_NFT"))
            QSKIP("Requires isolated network namespace; run test-firewall-container.sh");
#ifndef Q_OS_LINUX
        QSKIP("Linux nftables integration");
#else
        QTemporaryDir dir;
        const auto helper = QCoreApplication::applicationDirPath() + "/siem-firewall-helper";
        QJsonObject blocking{{"version", 2},
                             {"rules", QJsonArray{QJsonObject{{"name", "watchdog-test"},
                                                              {"direction", "output"},
                                                              {"source", "any"},
                                                              {"destination", "any"},
                                                              {"protocol", "tcp"},
                                                              {"port", 49999},
                                                              {"action", "drop"}}}}};
        auto candidate = dir.filePath("candidate.json");
        writePrivate(candidate, QJsonDocument(blocking).toJson());
        QCOMPARE(QProcess::execute(helper, {"--apply", candidate}), 0);
        QJsonObject state{
            {"active", QJsonObject{{"token", "default:0"}, {"policy", defaultEndpointPolicy()}}},
            {"pending", QJsonObject{{"token", "default:1"},
                                    {"applied", true},
                                    {"deadline", "2000-01-01T00:00:00.000Z"}}}};
        writePrivate(dir.filePath("policy-state.json"), QJsonDocument(state).toJson());
        QJsonObject config{{"state_dir", dir.path()}, {"manage_firewall", true}};
        QCOMPARE(PolicyController::watchdog(config, "default:1"), 0);
        auto restored = readObject(dir.filePath("policy-state.json"));
        QVERIFY(restored["pending"].toObject().isEmpty());
        QCOMPARE(restored["failed_token"].toString(), QString("default:1"));
        QProcess nft;
        nft.start("nft", {"list", "table", "inet", "sentinel_siem"});
        QVERIFY(nft.waitForFinished(5000));
        QVERIFY(!nft.readAllStandardOutput().contains("49999"));
#endif
    }
};
QTEST_GUILESS_MAIN(FleetTests)
#include "fleet_tests.moc"
