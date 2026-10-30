#include "agent.h"
#include "core/collector.h"
#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QHostInfo>
#include <QJsonDocument>
#include <QNetworkDatagram>
#include <QStandardPaths>
#include <QStorageInfo>
#include <QSysInfo>
#ifdef Q_OS_WIN
#include <windows.h>
#include <winevt.h>
#endif

namespace siem::fleet {
Agent::Agent(const QJsonObject &c, const QString &path, QObject *parent)
    : QObject(parent), config_(c),
      queue_(QDir(c["state_dir"].toString()).filePath("spool.sqlite"), c["queue_max_events"].toInt(100000),
             qint64(c["queue_max_mib"].toInt(256)) * 1024 * 1024),
      client_(c["server"].toObject(), this), policy_(c, path, this), scanner_(this) {
    const auto registration = queue_.state("registration");
    enrolled_ = registration["enrolled"].toBool() && registration["identity"].toString() ==
        certificateId(c["server"].toObject()["certificate"].toString());
    poll_.setSingleShot(true);
    connect(&poll_, &QTimer::timeout, this, &Agent::synchronize);
    connect(&sources_, &QTimer::timeout, this, &Agent::sourceTick);
    connect(&schedule_, &QTimer::timeout, this, [this] {
        const auto av = policy_.activePolicy()["antivirus"].toObject();
        const auto last =
            QDateTime::fromString(queue_.state("last_scan")["time"].toString(), Qt::ISODateWithMs);
        if (av["enabled"].toBool() && (!last.isValid() || last.addSecs(av["interval_minutes"].toInt(1440) *
                                                                       60) < QDateTime::currentDateTimeUtc()))
            scan();
    });
    connect(&syslog_, &QUdpSocket::readyRead, this, [this] {
        for (int n = 0; n < 100 && syslog_.hasPendingDatagrams(); ++n) {
            auto packet = syslog_.receiveDatagram(8192);
            enqueue(Collector::parse(packet.data(), QHostInfo::localHostName(), "Syslog"));
        }
        if (syslog_.hasPendingDatagrams())
            QMetaObject::invokeMethod(&syslog_, "readyRead", Qt::QueuedConnection);
    });
    connect(&journal_, &QProcess::readyReadStandardOutput, this, [this] {
        journalBuffer_ += journal_.readAllStandardOutput();
        if (journalBuffer_.size() > 2 * MaxFrame) {
            sourceError_ = "journald output exceeded limit";
            journal_.kill();
            journalBuffer_.clear();
            return;
        }
        while (journalBuffer_.contains('\n')) {
            const auto end = journalBuffer_.indexOf('\n');
            const auto line = journalBuffer_.left(end);
            journalBuffer_.remove(0, end + 1);
            auto j = QJsonDocument::fromJson(line).object();
            if (j.isEmpty())
                continue;
            Event event;
            event.source = "journald";
            event.host = QHostInfo::localHostName();
            event.category = "system";
            event.message = j["MESSAGE"].toString().left(8192);
            const auto priority = j["PRIORITY"].toString().toInt();
            event.severity = priority <= 2   ? "critical"
                             : priority == 3 ? "high"
                             : priority == 4 ? "medium"
                                             : "info";
            event.raw = {{"unit", j["_SYSTEMD_UNIT"]}, {"cursor", j["__CURSOR"]}};
            auto stamp = j["__REALTIME_TIMESTAMP"].toString().toLongLong();
            if (stamp > 0)
                event.time = QDateTime::fromMSecsSinceEpoch(stamp / 1000).toUTC();
            if (!enqueue(event)) {
                journal_.kill();
                journalBuffer_.clear();
                return;
            }
            queue_.setState("journal_cursor", {{"cursor", j["__CURSOR"]}});
        }
    });
    connect(&journal_, &QProcess::readyReadStandardError, this, [this] {
        auto error = QString::fromUtf8(journal_.readAllStandardError()).trimmed();
        if (!error.isEmpty())
            sourceError_ = error.left(1024);
    });
    connect(&scanner_, &Scanner::finished, this, [this](const ScanResult &result) {
        scanSummary_["scanned"] = scanSummary_["scanned"].toInt() + result.scanned;
        scanSummary_["findings"] = scanSummary_["findings"].toInt() + int(result.findings.size());
        scanSummary_["errors"] = scanSummary_["errors"].toInt() + int(result.errors.size());
        scanSummary_["clam_used"] = result.clamUsed;
        for (const auto &finding : result.findings) {
            Event event;
            event.source = "Antivirus";
            event.category = "malware";
            event.severity = "critical";
            event.message = "malware: " + finding.signature + " — " + finding.path;
            event.raw = {
                {"path", finding.path}, {"sha256", finding.sha256}, {"signature", finding.signature}};
            enqueue(event);
        }
        if (!result.errors.isEmpty()) {
            Event event;
            event.source = "Antivirus";
            event.category = "health";
            event.severity = "medium";
            event.message = result.errors.join("; ").left(8192);
            enqueue(event);
        }
        scanNext();
    });
}
Agent::~Agent() {
    scanner_.cancel();
    journal_.kill();
    journal_.waitForFinished(2000);
}
bool Agent::enqueue(Event event) {
    try {
        event.message = event.message.left(8192);
        if (event.host.isEmpty())
            event.host = QHostInfo::localHostName();
        queue_.enqueue(event);
        return true;
    } catch (const std::exception &e) {
        ++rejected_;
        sourceError_ = QString::fromUtf8(e.what());
        qWarning("Event not queued: %s", e.what());
        return false;
    }
}
void Agent::start() {
    policy_.recover();
    const int port = config_["syslog_port"].toInt(5514);
    require(port >= 0 && port <= 65535, "Invalid syslog port");
    if (port && !syslog_.bind(QHostAddress::LocalHost, quint16(port), QUdpSocket::DontShareAddress))
        sourceError_ = syslog_.errorString();
    Event event;
    event.source = "Sentinel Agent";
    event.message = "Background agent started";
    enqueue(event);
    poll_.start(0);
    sources_.start(5000);
    schedule_.start(60000);
    sourceTick();
}
QJsonObject Agent::health() const {
    auto h = policy_.health();
    h["version"] = QCoreApplication::applicationVersion();
    h["os"] = QSysInfo::prettyProductName();
    h["queue_events"] = queue_.count();
    h["queue_bytes"] = double(queue_.bytes());
    h["rejected_events"] = double(rejected_);
    h["source_error"] = sourceError_;
    h["scan_running"] = scanner_.busy();
    h["last_scan"] = queue_.state("last_scan");
    h["clamav_installed"] = !QStandardPaths::findExecutable("clamscan").isEmpty();
    h["disk_free_bytes"] = double(QStorageInfo(config_["state_dir"].toString()).bytesAvailable());
    return h;
}
void Agent::synchronize() {
    if (client_.busy()) {
        poll_.start(1000);
        return;
    }
    try {
        if (!enrolled_) {
            const auto token =
                QString::fromUtf8(readFile(config_["enrollment_token_file"].toString(), 4096)).trimmed();
            client_.call(
                "agent.enroll",
                {{"token", token}, {"hostname", QHostInfo::localHostName()}, {"platform", nativeBackend()}},
                [this](const QJsonObject &r, const QString &error) {
                    if (error.isEmpty() && r["enrolled"].toBool()) {
                        enrolled_ = true;
                        queue_.setState("registration", {{"enrolled", true}, {"identity", r["identity"]}});
                        failures_ = 0;
                    } else {
                        connectionError_ = error;
                        ++failures_;
                        qWarning("Enrollment: %s", qPrintable(error));
                    }
                    poll_.start(enrolled_ ? 0 : qMin(60000, 2000 * (1 << qMin(failures_, 5))));
                });
            return;
        }
        const auto batch = queue_.batch();
        const auto results = queue_.state("command_results")["outbox"].toArray();
        client_.call("agent.poll", {{"events", batch}, {"health", health()}, {"results", results}},
                     [this, batch, results](const QJsonObject &r, const QString &error) {
                         try {
                             if (!error.isEmpty()) {
                                 connectionError_ = error;
                                 ++failures_;
                                 qWarning("Server: %s", qPrintable(error));
                             } else {
                                 failures_ = 0;
                                 connectionError_.clear();
                                 QSet<QString> sent;
                                 for (auto v : batch)
                                     sent.insert(v.toObject()["id"].toString());
                                 for (auto v : r["ack"].toArray())
                                     require(sent.contains(v.toString()),
                                             "Server acknowledged an unsent event");
                                 queue_.acknowledge(r["ack"].toArray());
                                 auto state = queue_.state("command_results");
                                 auto outbox = state["outbox"].toArray();
                                 QJsonArray remaining;
                                 QSet<QString> delivered;
                                 for (auto v : results)
                                     delivered.insert(v.toObject()["id"].toString());
                                 for (auto v : outbox)
                                     if (!delivered.contains(v.toObject()["id"].toString()))
                                         remaining.append(v);
                                 state["outbox"] = remaining;
                                 queue_.setState("command_results", state);
                                 policy_.accept(r["policy"].toObject(), r["confirm"].toString());
                                 for (auto v : r["commands"].toArray()) {
                                     auto command = v.toObject();
                                     auto id = command["id"].toString();
                                     auto done = queue_.state("command_results")["completed"].toObject();
                                     if (done.contains(id))
                                         commandResult(id, done[id].toObject());
                                     else if (command["kind"].toString() == "scan" && !scanner_.busy() &&
                                              scanPaths_.isEmpty())
                                         scan(id);
                                 }
                             }
                         } catch (const std::exception &e) {
                             connectionError_ = QString::fromUtf8(e.what());
                             qWarning("Sync: %s", e.what());
                             ++failures_;
                         }
                         poll_.start(failures_            ? qMin(60000, 2000 * (1 << qMin(failures_, 5)))
                                     : queue_.count() > 0 ? 100
                                                          : 10000);
                     });
    } catch (const std::exception &e) {
        qWarning("Agent: %s", e.what());
        poll_.start(10000);
    }
}
void Agent::sourceTick() {
    if (!config_["collect_system"].toBool(true))
        return;
#ifdef Q_OS_WIN
    windowsEvents();
#else
    if (journal_.state() == QProcess::NotRunning &&
        queue_.count() < config_["queue_max_events"].toInt(100000))
        startJournal();
#endif
}
void Agent::startJournal() {
    const auto executable = QStandardPaths::findExecutable("journalctl");
    if (executable.isEmpty()) {
        sourceError_ = "journalctl unavailable";
        return;
    }
    QStringList args{"--follow", "--output=json", "--no-pager", "--all"};
    const auto cursor = queue_.state("journal_cursor")["cursor"].toString();
    if (cursor.isEmpty())
        args << "--since=now";
    else
        args << "--after-cursor=" + cursor;
    journalBuffer_.clear();
    journal_.start(executable, args);
}
void Agent::windowsEvents() {
#ifdef Q_OS_WIN
    for (const auto &channel : {QString("System"), QString("Application"), QString("Security")}) {
        auto cursor = queue_.state("eventlog_" + channel)["record"].toString().toULongLong();
        // First enrollment starts at the current tail; subsequent starts resume persisted record IDs.
        if (!cursor) {
            auto latest = EvtQuery(nullptr, reinterpret_cast<LPCWSTR>(channel.utf16()), L"*",
                                   EvtQueryChannelPath | EvtQueryReverseDirection);
            if (latest) {
                EVT_HANDLE event = nullptr;
                DWORD returned = 0;
                if (EvtNext(latest, 1, &event, 0, 0, &returned)) {
                    auto context = EvtCreateRenderContext(0, nullptr, EvtRenderContextSystem);
                    DWORD bytes = 0, count = 0;
                    EvtRender(context, event, EvtRenderEventValues, 0, nullptr, &bytes, &count);
                    QByteArray buffer(int(bytes), '\0');
                    if (EvtRender(context, event, EvtRenderEventValues, bytes, buffer.data(), &bytes,
                                  &count)) {
                        auto values = reinterpret_cast<EVT_VARIANT *>(buffer.data());
                        cursor = values[EvtSystemEventRecordId].UInt64Val;
                        queue_.setState("eventlog_" + channel, {{"record", QString::number(cursor)}});
                    }
                    EvtClose(context);
                    EvtClose(event);
                }
                EvtClose(latest);
            }
        }
        const auto expression = QString("*[System[EventRecordID > %1]]").arg(cursor);
        auto query = EvtQuery(nullptr, reinterpret_cast<LPCWSTR>(channel.utf16()),
                              reinterpret_cast<LPCWSTR>(expression.utf16()),
                              EvtQueryChannelPath | EvtQueryForwardDirection);
        if (!query) {
            sourceError_ =
                "Windows Event Log access failed: " + channel + " (" + QString::number(GetLastError()) + ")";
            continue;
        }
        EVT_HANDLE events[16];
        DWORD returned = 0;
        if (EvtNext(query, 16, events, 0, 0, &returned))
            for (DWORD n = 0; n < returned; ++n) {
                auto context = EvtCreateRenderContext(0, nullptr, EvtRenderContextSystem);
                DWORD bytes = 0, count = 0;
                EvtRender(context, events[n], EvtRenderEventValues, 0, nullptr, &bytes, &count);
                QByteArray valuesBuffer(int(bytes), '\0');
                if (EvtRender(context, events[n], EvtRenderEventValues, bytes, valuesBuffer.data(), &bytes,
                              &count)) {
                    auto values = reinterpret_cast<EVT_VARIANT *>(valuesBuffer.data());
                    Event event;
                    event.source = "Windows Event Log";
                    event.category = channel;
                    const auto level = values[EvtSystemLevel].ByteVal;
                    event.severity = level == 1   ? "critical"
                                     : level == 2 ? "high"
                                     : level == 3 ? "medium"
                                                  : "info";
                    event.raw = {{"event_id", int(values[EvtSystemEventID].UInt16Val)},
                                 {"record_id", QString::number(values[EvtSystemEventRecordId].UInt64Val)}};
                    DWORD xmlBytes = 0, xmlCount = 0;
                    EvtRender(nullptr, events[n], EvtRenderEventXml, 0, nullptr, &xmlBytes, &xmlCount);
                    QByteArray xml(int(xmlBytes), '\0');
                    if (EvtRender(nullptr, events[n], EvtRenderEventXml, xmlBytes, xml.data(), &xmlBytes,
                                  &xmlCount))
                        event.message =
                            QString::fromWCharArray(reinterpret_cast<const wchar_t *>(xml.constData()))
                                .left(8192);
                    if (enqueue(event))
                        queue_.setState(
                            "eventlog_" + channel,
                            {{"record", QString::number(values[EvtSystemEventRecordId].UInt64Val)}});
                    else {
                        for (DWORD j = n + 1; j < returned; ++j)
                            EvtClose(events[j]);
                        EvtClose(context);
                        EvtClose(events[n]);
                        break;
                    }
                }
                EvtClose(context);
                EvtClose(events[n]);
            }
        EvtClose(query);
    }
#endif
}
void Agent::commandResult(const QString &id, const QJsonObject &value) {
    if (id.isEmpty())
        return;
    auto state = queue_.state("command_results");
    auto result = value;
    result["id"] = id;
    auto completed = state["completed"].toObject();
    completed[id] = result;
    while (completed.size() > 128)
        completed.remove(completed.begin().key());
    auto outbox = state["outbox"].toArray();
    bool found = false;
    for (auto v : outbox)
        if (v.toObject()["id"] == id)
            found = true;
    if (!found)
        outbox.append(result);
    state["completed"] = completed;
    state["outbox"] = outbox;
    queue_.setState("command_results", state);
}
void Agent::scan(const QString &command) {
    if (scanner_.busy() || !scanPaths_.isEmpty())
        return;
    const auto av = policy_.activePolicy()["antivirus"].toObject();
    if (!av["enabled"].toBool()) {
        commandResult(command, {{"ok", false}, {"error", "Antivirus disabled by policy"}});
        return;
    }
    const auto allowed = config_["scan_roots"].toArray();
    for (auto v : av["paths"].toArray()) {
        const auto path = QFileInfo(v.toString()).canonicalFilePath();
        bool permitted = false;
        if (!path.isEmpty())
            for (auto root : allowed) {
                const auto base = QFileInfo(root.toString()).canonicalFilePath();
                if (!base.isEmpty() &&
                    (path == base || path.startsWith(base.endsWith('/') ? base : base + '/')))
                    permitted = true;
            }
        if (!permitted) {
            scanPaths_.clear();
            commandResult(command, {{"ok", false},
                                    {"error", "Scan path missing or outside locally approved scan_roots"}});
            return;
        }
        scanPaths_ << path;
    }
    if (scanPaths_.isEmpty()) {
        commandResult(command, {{"ok", false}, {"error", "No scan paths configured"}});
        return;
    }
    scanCommand_ = command;
    scanSummary_ = {{"scanned", 0}, {"findings", 0}, {"errors", 0}};
    scanNext();
}
void Agent::scanNext() {
    if (scanPaths_.isEmpty()) {
        scanSummary_["time"] = now();
        scanSummary_["ok"] = scanSummary_["errors"].toInt() == 0 && scanSummary_["clam_used"].toBool();
        queue_.setState("last_scan", scanSummary_);
        commandResult(scanCommand_, scanSummary_);
        scanCommand_.clear();
        return;
    }
    QStringList exclusions;
    for (auto v : policy_.activePolicy()["antivirus"].toObject()["exclusions"].toArray())
        exclusions << v.toString();
    scanner_.start(scanPaths_.takeFirst(), {}, true, exclusions);
}
} // namespace siem::fleet
