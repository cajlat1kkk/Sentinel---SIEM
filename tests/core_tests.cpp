#include "core/collector.h"
#include "core/firewall.h"
#include "core/scanner.h"
#include "core/store.h"
#include "network/packet.h"
#include <QFile>
#include <QJsonDocument>
#include <QNetworkDatagram>
#include <QTemporaryDir>
#include <QtTest>
using namespace siem;
static QByteArray frame(const QByteArray &payload) {
    QByteArray b(14 + 20 + 20, 0);
    b[12] = 8;
    b[13] = 0;
    b[14] = 0x45;
    int len = 40 + int(payload.size());
    b[16] = char(len >> 8);
    b[17] = char(len);
    b[23] = 6;
    b[26] = 10;
    b[29] = 1;
    b[30] = 10;
    b[33] = 2;
    b[34] = char(0xc3);
    b[35] = 0x50;
    b[36] = 0;
    b[37] = 80;
    b[46] = 0x50;
    return b + payload;
}
static QJsonObject rule() {
    return {{"name", "Block HTTP"}, {"direction", "forward"}, {"source", "10.0.0.0/8"},
            {"destination", "any"}, {"protocol", "tcp"},      {"port", 80},
            {"action", "drop"},     {"enabled", true}};
}
class CoreTests : public QObject {
    Q_OBJECT
  private slots:
    void persistenceAndCorrelation() {
        QTemporaryDir dir;
        auto path = dir.filePath("test.db");
        {
            Store s(path);
            Event e;
            e.source = "Syslog";
            e.host = "node-a";
            e.message = "Failed password for root";
            for (int i = 0; i < 4; ++i)
                s.ingest(e);
            QCOMPARE(s.scalar("SELECT COUNT(*) FROM incidents").toInt(), 0);
            s.ingest(e);
            QCOMPARE(s.scalar("SELECT COUNT(*) FROM incidents").toInt(), 1);
            s.ingest(e);
            QCOMPARE(s.scalar("SELECT COUNT(*) FROM incidents").toInt(), 1);
            auto id = s.scalar("SELECT id FROM incidents").toLongLong();
            s.setIncidentStatus(id, "investigating", "Inspect source");
            QCOMPARE(s.scalar("SELECT status FROM incidents WHERE id=?", {id}).toString(),
                     QString("investigating"));
            QVERIFY_EXCEPTION_THROWN(s.setIncidentStatus(id, "invalid", ""), std::runtime_error);
            QCOMPARE(s.scalar("SELECT COUNT(*) FROM assets").toInt(), 1);
        }
        Store reopened(path);
        QCOMPARE(reopened.scalar("SELECT COUNT(*) FROM events").toInt(), 6);
        QCOMPARE(reopened.scalar("SELECT COUNT(*) FROM rules").toInt(), 2);
        QVERIFY(QJsonDocument::fromJson(reopened.exportJson().toUtf8()).isObject());
    }
    void parsing() {
        auto e = Collector::parse(
            R"({"event_type":"alert","src_ip":"10.0.0.4","alert":{"signature":"SQL injection","severity":1}})");
        QCOMPARE(e.source, QString("Suricata"));
        QCOMPARE(e.host, QString("10.0.0.4"));
        QCOMPARE(e.severity, QString("critical"));
        auto s = Collector::parse("<34>1 2026-10-27T10:00:00Z gateway ssh 100 AUTH - failed password");
        QCOMPARE(s.host, QString("gateway"));
        QCOMPARE(s.severity, QString("critical"));
        QVERIFY(s.time.isValid());
        auto invalid = Collector::parse("{broken json");
        QCOMPARE(invalid.message, QString("{broken json"));
    }
    void udpAndImport() {
        QTemporaryDir dir;
        Store store(dir.filePath("db"));
        Collector c(store);
        QString error;
        QVERIFY2(c.start(0, &error), qPrintable(error));
        QUdpSocket sender;
        sender.writeDatagram("<14>hello from UDP", QHostAddress::LocalHost, c.port());
        QTRY_COMPARE(store.scalar("SELECT COUNT(*) FROM events").toInt(), 1);
        QFile file(dir.filePath("events.jsonl"));
        QVERIFY(file.open(QIODevice::WriteOnly));
        file.write("{\"message\":\"imported\",\"host\":\"test\"}\n\nplain line\n");
        file.close();
        QCOMPARE(c.importFile(file.fileName(), &error), 2);
        QCOMPARE(store.scalar("SELECT COUNT(*) FROM events").toInt(), 3);
        c.stop();
        QVERIFY(!c.active());
    }
    void firewallValidation() {
        auto r = rule();
        QVERIFY(validateFirewallRule(r).isEmpty());
        QString error;
        auto text = compileNft({r}, &error);
        QVERIFY(error.isEmpty());
        QVERIFY(text.contains("ip saddr 10.0.0.0/8"));
        QVERIFY(!text.contains("flush ruleset"));
        QVERIFY(text.contains("tcp dport 80 counter drop"));
        r["source"] = "any; flush ruleset";
        QVERIFY(!validateFirewallRule(r).isEmpty());
        r = rule();
        r["destination"] = "::1";
        QVERIFY(!validateFirewallRule(r).isEmpty());
        r = rule();
        r["port"] = 70000;
        QVERIFY(!validateFirewallRule(r).isEmpty());
        r = rule();
        r["port"] = 2.5;
        QVERIFY(!validateFirewallRule(r).isEmpty());
        r = rule();
        r["protocol"] = "any";
        QVERIFY(!validateFirewallRule(r).isEmpty());
        r = rule();
        r["enabled"] = false;
        text = compileNft({r}, &error);
        QVERIFY(!text.contains("dport"));
    }
    void packetInspection() {
        auto bytes = frame("GET /?q=%27%20OR%201=1 HTTP/1.1\r\nHost: lab\r\n\r\n");
        auto p = inspectPacket(bytes);
        QVERIFY(p.valid);
        QCOMPARE(p.source, QString("10.0.0.1"));
        QCOMPARE(p.destinationPort, quint16(80));
        QVERIFY(p.signature.contains("SQL injection"));
        QVERIFY(packetBlocked(p, {}, true));
        QVERIFY(packetBlocked(p, {rule()}, false));
        auto allow = rule();
        allow["action"] = "accept";
        QVERIFY(!packetBlocked(p, {allow, rule()}, false));
        QVERIFY(!inspectPacket(bytes.left(30)).valid);
        QVERIFY(inspectPacket(frame("GET / HTTP/1.1\r\n\r\n")).signature.isEmpty());
        auto frag = bytes;
        frag[20] = 0x20;
        auto f = inspectPacket(frag);
        QVERIFY(f.fragmented);
        QVERIFY(f.signature.isEmpty());
        auto xss = inspectPacket(frame("GET /?q=%3Cscript%3E HTTP/1.1\r\n\r\n"));
        QVERIFY(xss.signature.contains("XSS"));
    }
    void antivirusAndQuarantine() {
        QTemporaryDir dir;
        Store store(dir.filePath("db"));
        auto path = dir.filePath("sample.txt");
        QFile file(path);
        QVERIFY(file.open(QIODevice::WriteOnly));
        file.write(QByteArray::fromBase64(
            "WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo="));
        file.close();
        std::atomic_bool cancel{false};
        auto result = Scanner::scan(path, {}, cancel, false);
        QCOMPARE(result.scanned, 1);
        QCOMPARE(result.findings.size(), 1);
        QCOMPARE(result.findings[0].signature, QString("EICAR-Test-File"));
        QString error;
        auto id = Scanner::quarantine(store, result.findings[0], dir.filePath("quarantine"), &error);
        QVERIFY2(id > 0, qPrintable(error));
        QVERIFY(!QFile::exists(path));
        QVERIFY(Scanner::restore(store, id, path, &error));
        QVERIFY(QFile::exists(path));
        QVERIFY(!Scanner::restore(store, id, path, &error));
        QVERIFY(file.open(QIODevice::WriteOnly));
        file.write("clean changed file");
        file.close();
        QCOMPARE(Scanner::quarantine(store, result.findings[0], dir.filePath("quarantine"), &error),
                 qint64(0));
        auto clean = Scanner::scan(path, {}, cancel, false);
        QVERIFY(clean.findings.isEmpty());
        auto hash = Scanner::hashFile(path);
        auto custom = Scanner::scan(path, {{hash, "Test-Hash"}}, cancel, false);
        QCOMPARE(custom.findings.size(), 1);
    }
    void clamavIntegration() {
        if (qEnvironmentVariableIsEmpty("SIEM_TEST_CLAMAV"))
            QSKIP("Run scripts/test-clamav-container.sh with its harmless custom ClamAV signature");
        QTemporaryDir dir;
        QFile file(dir.filePath("harmless fixture with spaces.txt"));
        QVERIFY(file.open(QIODevice::WriteOnly));
        file.write("SENTINEL-CLAMAV-INTEGRATION-FIXTURE-ONLY");
        file.close();
        std::atomic_bool cancel{false};
        const auto builtin = Scanner::scan(file.fileName(), {}, cancel, false);
        QVERIFY(builtin.findings.isEmpty());
        const auto result = Scanner::scan(file.fileName(), {}, cancel, true);
        QVERIFY(result.clamUsed);
        QVERIFY2(result.errors.isEmpty(), qPrintable(result.errors.join('\n')));
        QCOMPARE(result.findings.size(), 1);
        QVERIFY(result.findings.first().signature.contains("Sentinel.Integration"));
        QCOMPARE(result.findings.first().path, file.fileName());
        QCOMPARE(result.findings.first().sha256, Scanner::hashFile(file.fileName()));
    }
    void postgres() {
        if (qEnvironmentVariableIsEmpty("SIEM_TEST_PG_PORT"))
            QSKIP("Set SIEM_TEST_PG_PORT for an isolated PostgreSQL integration test");
        DatabaseConfig c;
        c.port = qEnvironmentVariableIntValue("SIEM_TEST_PG_PORT");
        c.name = "sentinel_test";
        c.user = qEnvironmentVariable("USER");
        Store store(c);
        Event e;
        e.source = "Test";
        e.host = "pg-integration";
        e.message = "malware test fixture";
        e.severity = "critical";
        auto id = store.ingest(e);
        QVERIFY(id > 0);
        QCOMPARE(store.scalar("SELECT message FROM events WHERE id=?", {id}).toString(), e.message);
        QVERIFY(store.scalar("SELECT COUNT(*) FROM incidents WHERE event_id=?", {id}).toInt() > 0);
        auto r = rule();
        QVERIFY(!store.exportJson().isEmpty());
        store.audit("test.complete", "PostgreSQL persistence and correlation verified");
    }
};
QTEST_GUILESS_MAIN(CoreTests)
#include "core_tests.moc"
