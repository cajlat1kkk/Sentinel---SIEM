#include "repository.h"
#include "core/collector.h"
#include <QJsonDocument>
#include <QRandomGenerator>
#include <QRegularExpression>

namespace siem::fleet {
static QString json(const QJsonObject &o) {
    return QString::fromUtf8(QJsonDocument(o).toJson(QJsonDocument::Compact));
}
static QJsonArray records(const QList<QVariantMap> &rows) {
    QJsonArray a;
    for (const auto &r : rows)
        a.append(QJsonObject::fromVariantMap(r));
    return a;
}
static bool fingerprintValid(const QString &id) {
    return QRegularExpression("^[0-9a-f]{64}$").match(id).hasMatch();
}
Repository::Repository(Store &s) : store_(s) {
    store_.atomic([&] {
        store_.exec("CREATE TABLE IF NOT EXISTS fleet_operators(identity TEXT PRIMARY KEY,name TEXT NOT "
                    "NULL,role TEXT NOT NULL,revoked INTEGER NOT NULL DEFAULT 0)");
        store_.exec("CREATE TABLE IF NOT EXISTS fleet_groups(name TEXT PRIMARY KEY,revision INTEGER NOT NULL "
                    "DEFAULT 0,policy TEXT NOT NULL)");
        store_.exec("CREATE TABLE IF NOT EXISTS fleet_devices(identity TEXT PRIMARY KEY,hostname TEXT NOT "
                    "NULL,platform TEXT NOT NULL,group_name TEXT NOT NULL REFERENCES "
                    "fleet_groups(name),enrolled TEXT NOT NULL,last_seen TEXT NOT NULL,revoked INTEGER NOT "
                    "NULL DEFAULT 0,health TEXT NOT NULL DEFAULT '{}')");
        store_.exec("CREATE TABLE IF NOT EXISTS fleet_enrollments(token_hash TEXT PRIMARY KEY,identity TEXT "
                    "NOT NULL,group_name TEXT NOT NULL REFERENCES fleet_groups(name),expires TEXT NOT "
                    "NULL,used INTEGER NOT NULL DEFAULT 0)");
        store_.exec("CREATE TABLE IF NOT EXISTS fleet_commands(id TEXT PRIMARY KEY,device TEXT NOT NULL "
                    "REFERENCES fleet_devices(identity),kind TEXT NOT NULL,payload TEXT NOT NULL,state TEXT "
                    "NOT NULL DEFAULT 'queued',created TEXT NOT NULL,result TEXT NOT NULL DEFAULT '{}')");
        store_.exec(
            "CREATE INDEX IF NOT EXISTS fleet_commands_pending ON fleet_commands(device,state,created)");
        store_.exec("INSERT INTO fleet_groups(name,revision,policy) VALUES('default',0,?) ON CONFLICT(name) "
                    "DO NOTHING",
                    {json(defaultEndpointPolicy())});
        store_.exec(
            "INSERT INTO schema_migrations(version,applied) VALUES(2,?) ON CONFLICT(version) DO NOTHING",
            {now()});
    });
}
void Repository::addOperator(const QString &id, const QString &name, const QString &role) {
    require(fingerprintValid(id) && !name.isEmpty() && name.size() <= 128 &&
                QStringList{"admin", "analyst"}.contains(role),
            "Invalid operator");
    require(!store_.scalar("SELECT identity FROM fleet_devices WHERE identity=?", {id}).isValid(),
            "Device certificate cannot be an operator");
    store_.atomic([&] {
        store_.exec("INSERT INTO fleet_operators(identity,name,role) VALUES(?,?,?) ON CONFLICT(identity) DO "
                    "UPDATE SET name=excluded.name,role=excluded.role,revoked=0",
                    {id, name, role});
        audit("local-bootstrap", "operator.provision", {{"identity", id}, {"name", name}, {"role", role}});
    });
}
void Repository::audit(const QString &identity, const QString &action, const QJsonObject &detail) {
    store_.audit("fleet." + action, json({{"actor", identity}, {"detail", detail}}));
}
QJsonObject Repository::policy(const QString &group) const {
    auto r = store_.rows("SELECT name,revision,policy FROM fleet_groups WHERE name=?", {group});
    require(!r.isEmpty(), "Group not found");
    return {{"group", group},
            {"revision", r[0]["revision"].toInt()},
            {"token", group + ":" + r[0]["revision"].toString()},
            {"policy", QJsonDocument::fromJson(r[0]["policy"].toString().toUtf8()).object()}};
}
QJsonObject Repository::enroll(const QString &id, const QJsonObject &p) {
    auto device = store_.rows("SELECT revoked FROM fleet_devices WHERE identity=?", {id});
    if (!device.isEmpty()) {
        require(!device[0]["revoked"].toBool(), "Device revoked");
        return {{"enrolled", true}, {"identity", id}};
    }
    require(!store_.scalar("SELECT identity FROM fleet_operators WHERE identity=?", {id}).isValid(),
            "Operator certificate cannot enroll as a device");
    const auto token = p["token"].toString();
    const auto host = p["hostname"].toString();
    const auto platform = p["platform"].toString();
    require(token.size() == 64 && !host.isEmpty() && host.size() <= 256 &&
                QStringList{"linux", "windows"}.contains(platform),
            "Invalid enrollment");
    store_.atomic([&] {
        // Conditional UPDATE RETURNING makes a token single-use, even across server processes.
        const auto rows = store_.rows("UPDATE fleet_enrollments SET used=1 WHERE token_hash=? AND identity=? "
                                      "AND used=0 AND expires>? RETURNING group_name",
                                      {digest(token.toUtf8()), id, now()});
        require(!rows.isEmpty(), "Enrollment denied: token expired, used or bound to another certificate");
        store_.exec("INSERT INTO fleet_devices(identity,hostname,platform,group_name,enrolled,last_seen) "
                    "VALUES(?,?,?,?,?,?)",
                    {id, host, platform, rows[0]["group_name"], now(), now()});
        audit(id, "device.enroll", {{"hostname", host}, {"platform", platform}});
    });
    return {{"enrolled", true}, {"identity", id}};
}
QJsonObject Repository::poll(const QString &id, const QJsonObject &p) {
    const auto devices = store_.rows("SELECT * FROM fleet_devices WHERE identity=? AND revoked=0", {id});
    require(!devices.isEmpty(), "Device not enrolled or revoked");
    const auto device = devices[0];
    const auto events = p["events"].toArray();
    require(events.size() <= BatchSize, "Too many events");
    const auto health = p["health"].toObject();
    require(json(health).size() <= 16384, "Health report too large");
    QJsonArray ack;
    for (const auto &v : events) {
        require(v.isObject(), "Invalid event record");
        auto r = v.toObject();
        auto key = r["id"].toString();
        require(QRegularExpression("^[0-9a-f-]{36}$").match(key).hasMatch() && r["event"].isObject(),
                "Invalid event id");
        const auto bytes = QJsonDocument(r["event"].toObject()).toJson(QJsonDocument::Compact);
        require(bytes.size() < 16384, "Event too large");
        auto e = Collector::parse(bytes);
        e.raw.insert("device_identity", id);
        e.raw.insert("reported_host", e.host);
        e.host = device["hostname"].toString();
        store_.ingest(e, id + ":" + key);
        ack.append(key);
    }
    require(p["results"].toArray().size() <= 16, "Too many command results");
    for (const auto &v : p["results"].toArray()) {
        auto result = v.toObject();
        require(json(result).size() < 8192, "Command result too large");
        auto rows = store_.rows("UPDATE fleet_commands SET state='complete',result=? WHERE id=? AND device=? "
                                "AND state='queued' RETURNING id",
                                {json(result), result["id"].toString(), id});
        if (!rows.isEmpty())
            audit(id, "command.result", result);
    }
    store_.exec("UPDATE fleet_devices SET last_seen=?,health=? WHERE identity=?", {now(), json(health), id});
    auto desired = policy(device["group_name"].toString());
    auto commands = records(store_.rows("SELECT id,kind,payload FROM fleet_commands WHERE device=? AND "
                                        "state='queued' ORDER BY created LIMIT 8",
                                        {id}));
    return {{"ack", ack},
            {"policy", desired},
            {"commands", commands},
            {"confirm", health["policy_state"].toString() == "pending" &&
                                health["policy_token"].toString() == desired["token"].toString()
                            ? desired["token"]
                            : QJsonValue("")},
            {"server_time", now()}};
}
QJsonObject Repository::dispatch(const QString &id, const QString &method, const QJsonObject &p) {
    require(fingerprintValid(id), "Invalid peer identity");
    if (method == "agent.enroll")
        return enroll(id, p);
    if (method == "agent.poll")
        return poll(id, p);
    auto operators =
        store_.rows("SELECT name,role FROM fleet_operators WHERE identity=? AND revoked=0", {id});
    require(!operators.isEmpty(), "Operator access denied");
    const auto role = operators[0]["role"].toString();
    const QStringList readMethods{"session",       "devices.list",   "groups.list",     "policies.get",
                                  "events.list",   "incidents.list", "rules.list",      "audit.list",
                                  "commands.list", "overview",       "incidents.update"};
    require(role == "admin" || readMethods.contains(method), "Administrator role required");
    if (method == "session")
        return {{"name", operators[0]["name"].toString()}, {"role", role}, {"identity", id}};
    if (method == "overview")
        return {
            {"devices", store_.scalar("SELECT COUNT(*) FROM fleet_devices WHERE revoked=0").toInt()},
            {"online", store_
                           .scalar("SELECT COUNT(*) FROM fleet_devices WHERE revoked=0 AND last_seen>?",
                                   {QDateTime::currentDateTimeUtc().addSecs(-90).toString(Qt::ISODateWithMs)})
                           .toInt()},
            {"events", store_
                           .scalar("SELECT COUNT(*) FROM events WHERE received>?",
                                   {QDateTime::currentDateTimeUtc().addDays(-1).toString(Qt::ISODateWithMs)})
                           .toDouble()},
            {"incidents",
             store_.scalar("SELECT COUNT(*) FROM incidents WHERE status IN ('open','investigating')")
                 .toInt()}};
    const int offset = qBound(0, p["offset"].toInt(), 10000000);
    const int limit = qBound(1, p["limit"].toInt(50), 100);
    if (method == "devices.list")
        return {{"rows", records(store_.rows(
                             "SELECT * FROM fleet_devices ORDER BY hostname,identity LIMIT ? OFFSET ?",
                             {limit, offset}))}};
    if (method == "groups.list")
        return {
            {"rows", records(store_.rows("SELECT name,revision FROM fleet_groups ORDER BY name LIMIT 500"))}};
    if (method == "policies.get")
        return policy(p["group"].toString("default"));
    if (method == "events.list") {
        QString where = " WHERE 1=1";
        QVariantList args;
        const auto search = p["search"].toString().left(256);
        if (!search.isEmpty()) {
            where += " AND (LOWER(message) LIKE ? OR LOWER(host) LIKE ?)";
            args << "%" + search.toLower() + "%" << "%" + search.toLower() + "%";
        }
        if (!p["severity"].toString().isEmpty()) {
            where += " AND severity=?";
            args << p["severity"].toString();
        }
        args << limit << offset;
        return {{"rows",
                 records(store_.rows("SELECT id,time,host,source,category,severity,message,ip FROM events" +
                                         where + " ORDER BY id DESC LIMIT ? OFFSET ?",
                                     args))}};
    }
    if (method == "incidents.list")
        return {{"rows", records(store_.rows("SELECT * FROM incidents ORDER BY id DESC LIMIT ? OFFSET ?",
                                             {limit, offset}))}};
    if (method == "audit.list")
        return {{"rows", records(store_.rows("SELECT * FROM audit ORDER BY id DESC LIMIT ? OFFSET ?",
                                             {limit, offset}))}};
    if (method == "rules.list")
        return {{"rows", records(store_.rows("SELECT * FROM rules ORDER BY id LIMIT 500"))}};
    if (method == "commands.list")
        return {{"rows",
                 records(store_.rows("SELECT * FROM fleet_commands ORDER BY created DESC LIMIT ? OFFSET ?",
                                     {limit, offset}))}};
    if (method == "enrollment.create") {
        const auto target = p["identity"].toString();
        const auto group = p["group"].toString("default");
        require(fingerprintValid(target), "Certificate SHA-256 fingerprint required");
        policy(group);
        QByteArray bytes(32, '\0');
        for (int n = 0; n < 32; n += 4) {
            auto word = QRandomGenerator::system()->generate();
            for (int j = 0; j < 4; ++j)
                bytes[n + j] = char(word >> (j * 8));
        }
        const auto token = QString::fromLatin1(bytes.toHex());
        const auto expires = QDateTime::currentDateTimeUtc().addSecs(3600).toString(Qt::ISODateWithMs);
        store_.atomic([&] {
            store_.exec(
                "INSERT INTO fleet_enrollments(token_hash,identity,group_name,expires) VALUES(?,?,?,?)",
                {digest(token.toUtf8()), target, group, expires});
            audit(id, method, {{"identity", target}, {"group", group}, {"expires", expires}});
        });
        return {{"token", token}, {"expires", expires}};
    }
    if (method == "groups.create") {
        const auto group = p["group"].toString();
        require(QRegularExpression("^[a-zA-Z0-9_-]{1,64}$").match(group).hasMatch(),
                "Group name: 1–64 letters, digits, '-' or '_'");
        store_.atomic([&] {
            store_.exec("INSERT INTO fleet_groups(name,policy) VALUES(?,?)",
                        {group, json(defaultEndpointPolicy())});
            audit(id, method, p);
        });
        return {{"group", group}};
    }
    if (method == "policies.set") {
        const auto group = p["group"].toString();
        auto value = p["policy"].toObject();
        auto error = validateEndpointPolicy(value);
        require(error.isEmpty(), error);
        require(json(value).size() < 256 * 1024, "Policy too large");
        store_.atomic([&] {
            auto r = store_.rows("UPDATE fleet_groups SET revision=revision+1,policy=? WHERE name=? AND "
                                 "revision=? RETURNING revision",
                                 {json(value), group, p["expected_revision"].toInt(-1)});
            require(!r.isEmpty(), "Policy changed by another administrator; reload before saving");
            audit(id, method,
                  {{"group", group},
                   {"revision", r[0]["revision"].toInt()},
                   {"sha256", digest(json(value).toUtf8())}});
        });
        return policy(group);
    }
    if (method == "devices.group" || method == "devices.revoke" || method == "operators.revoke") {
        const auto target = p["identity"].toString();
        require(fingerprintValid(target), "Invalid identity");
        if (method == "operators.revoke")
            require(target != id, "Cannot revoke own session");
        store_.atomic([&] {
            QList<QVariantMap> r;
            if (method == "devices.group") {
                policy(p["group"].toString());
                r = store_.rows(
                    "UPDATE fleet_devices SET group_name=? WHERE identity=? AND revoked=0 RETURNING identity",
                    {p["group"].toString(), target});
            } else if (method == "devices.revoke")
                r = store_.rows("UPDATE fleet_devices SET revoked=1 WHERE identity=? RETURNING identity",
                                {target});
            else
                r = store_.rows("UPDATE fleet_operators SET revoked=1 WHERE identity=? RETURNING identity",
                                {target});
            require(!r.isEmpty(), "Identity not found");
            audit(id, method, p);
        });
        return {{"updated", true}};
    }
    if (method == "commands.scan") {
        auto device = p["identity"].toString();
        require(store_.scalar("SELECT identity FROM fleet_devices WHERE identity=? AND revoked=0", {device})
                    .isValid(),
                "Device unavailable");
        require(
            store_.scalar("SELECT COUNT(*) FROM fleet_commands WHERE device=? AND state='queued'", {device})
                    .toInt() < 8,
            "Device already has pending commands");
        auto command = uuid();
        store_.atomic([&] {
            store_.exec(
                "INSERT INTO fleet_commands(id,device,kind,payload,created) VALUES(?,?,'scan','{}',?)",
                {command, device, now()});
            audit(id, method, {{"id", command}, {"device", device}});
        });
        return {{"id", command}};
    }
    if (method == "incidents.update") {
        const auto status = p["status"].toString();
        require(QStringList{"open", "investigating", "resolved", "false_positive"}.contains(status),
                "Invalid incident status");
        store_.atomic([&] {
            auto rows = store_.rows("UPDATE incidents SET status=?,note=? WHERE id=? RETURNING id",
                                    {status, p["note"].toString().left(4096), p["id"].toVariant()});
            require(!rows.isEmpty(), "Incident not found");
            audit(id, method, p);
        });
        return {{"updated", true}};
    }
    if (method == "rules.save") {
        require(!p["name"].toString().trimmed().isEmpty() && !p["pattern"].toString().isEmpty() &&
                    p["pattern"].toString().size() <= 256,
                "Rule name and pattern required");
        require(p["threshold"].toInt() > 0 && p["threshold"].toInt() <= 10000 &&
                    p["window_seconds"].toInt() > 0 && p["window_seconds"].toInt() <= 86400,
                "Invalid rule bounds");
        require(QStringList{"info", "low", "medium", "high", "critical"}.contains(p["severity"].toString()),
                "Invalid severity");
        store_.atomic([&] {
            QVariantList args{p["name"].toString().left(128), p["pattern"].toString(),
                              p["threshold"].toInt(),         p["window_seconds"].toInt(),
                              p["severity"].toString(),       p["enabled"].toBool(true) ? 1 : 0};
            if (p["id"].toInt() > 0) {
                args << p["id"].toInt();
                store_.exec("UPDATE rules SET "
                            "name=?,pattern=?,threshold=?,window_seconds=?,severity=?,enabled=? WHERE id=?",
                            args);
            } else
                store_.exec("INSERT INTO rules(name,pattern,threshold,window_seconds,severity,enabled) "
                            "VALUES(?,?,?,?,?,?)",
                            args);
            audit(id, method, p);
        });
        return {{"updated", true}};
    }
    throw std::runtime_error("Unknown method");
}
} // namespace siem::fleet
