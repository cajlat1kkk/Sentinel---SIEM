#include "firewall.h"
#include <QHostAddress>
#include <QRegularExpression>
#include <QSet>
#include <cmath>
namespace siem {
namespace {
QString unexpected(const QJsonObject &object, const QSet<QString> &allowed) {
    for (auto it = object.begin(); it != object.end(); ++it)
        if (!allowed.contains(it.key()))
            return "Неизвестный параметр: " + it.key();
    return {};
}
bool address(const QString &s) {
    if (s == "any")
        return true;
    static const QRegularExpression literal("^[0-9a-fA-F:.]+(/[0-9]{1,3})?$");
    if (!literal.match(s).hasMatch())
        return false;
    return s.contains('/') ? QHostAddress::parseSubnet(s).second >= 0 : !QHostAddress(s).isNull();
}
bool integer(const QJsonValue &v, int min, int max) {
    return v.isDouble() && std::isfinite(v.toDouble()) && v.toDouble() >= min && v.toDouble() <= max &&
           std::floor(v.toDouble()) == v.toDouble();
}
bool iface(const QString &s) {
    static const QRegularExpression allowed("^[a-zA-Z0-9_.:-]{1,15}$");
    return s == "any" || allowed.match(s).hasMatch();
}
bool portsValid(const QString &ports) {
    if (ports == "any")
        return true;
    if (ports.isEmpty() || ports.size() > 1024)
        return false;
    static const QRegularExpression item("^([0-9]{1,5})(?:-([0-9]{1,5}))?$");
    const auto parts = ports.split(',');
    if (parts.size() > 64)
        return false;
    for (const auto &part : parts) {
        const auto match = item.match(part);
        if (!match.hasMatch())
            return false;
        const int a = match.captured(1).toInt();
        const int b = match.captured(2).isEmpty() ? a : match.captured(2).toInt();
        if (a < 1 || b > 65535 || a > b)
            return false;
    }
    return true;
}
QJsonObject merged(QJsonObject base, const QJsonObject &overrides) {
    for (auto it = overrides.begin(); it != overrides.end(); ++it)
        base[it.key()] = it.value();
    return base;
}
QJsonObject completeRule(const QJsonObject &r) {
    QJsonObject defaults{{"source_ports", "any"},
                         {"destination_ports", firewallPorts(r, false)},
                         {"in_interface", "any"},
                         {"out_interface", "any"},
                         {"log", false},
                         {"rate_limit", 0},
                         {"comment", ""},
                         {"enabled", true},
                         {"port", 0}};
    return merged(defaults, r);
}
bool inspectionActive(const QJsonObject &p) {
    const auto i = p["inspection"].toObject();
    return i["sql_injection"].toBool() || i["xss"].toBool() || i["path_traversal"].toBool() ||
           i["block_fragments"].toBool() || !i["blocked_domains"].toArray().isEmpty();
}
bool natActive(const QJsonObject &p) {
    for (const auto &v : p["nat"].toArray())
        if (v.toObject()["enabled"].toBool(true))
            return true;
    return false;
}
QString validateNat(const QJsonObject &r) {
    const auto unknown = unexpected(r, {"name", "type", "interface", "protocol", "source", "destination",
                                        "port", "to_address", "to_port", "enabled"});
    if (!unknown.isEmpty())
        return unknown;
    if (!r["name"].isString() || r["name"].toString().trimmed().isEmpty() ||
        r["name"].toString().size() > 100)
        return "NAT: укажите имя (до 100 символов)";
    if (!QStringList{"dnat", "snat", "masquerade"}.contains(r["type"].toString()))
        return "NAT: неизвестный тип";
    if (!r["enabled"].isBool() || !iface(r["interface"].toString()))
        return "NAT: некорректный интерфейс или enabled";
    if (!QStringList{"any", "tcp", "udp"}.contains(r["protocol"].toString()))
        return "NAT: поддерживаются TCP, UDP или any";
    for (const auto &key : {"source", "destination"}) {
        const auto a = r[key].toString();
        if (!address(a) || a.contains(':'))
            return "NAT: поддерживаются только IPv4/CIDR или any";
    }
    if (!integer(r["port"], 0, 65535) || !integer(r["to_port"], 0, 65535))
        return "NAT: порт должен быть целым числом 0–65535";
    if ((r["port"].toInt() || r["to_port"].toInt()) && r["protocol"] == "any")
        return "NAT: для портов выберите TCP или UDP";
    const auto target = r["to_address"].toString();
    if (!r["to_address"].isString())
        return "NAT: адрес назначения должен быть строкой";
    if (r["type"] == "masquerade") {
        if (!target.isEmpty() || r["to_port"].toInt())
            return "Masquerade: to_address и to_port не используются";
    } else if (!address(target) || target == "any" || target.contains('/') || target.contains(':'))
        return "NAT: to_address должен быть одиночным IPv4";
    return {};
}
QString nftPorts(const QString &ports) {
    // Re-render validated numeric tokens; this also avoids nft interpreting leading zeroes.
    QStringList normalized;
    for (const auto &part : ports.split(',')) {
        const auto range = part.split('-');
        normalized.append(QString::number(range[0].toInt()) +
                          (range.size() == 2 ? "-" + QString::number(range[1].toInt()) : ""));
    }
    return normalized.size() == 1 ? normalized.first() : "{ " + normalized.join(", ") + " }";
}
QString nftMatch(const QJsonObject &r) {
    QString match;
    for (const auto &entry : {qMakePair("in_interface", "iifname"), qMakePair("out_interface", "oifname")})
        if (r[entry.first].toString("any") != "any")
            match += QString("%1 \"%2\" ").arg(entry.second, r[entry.first].toString());
    for (const auto &entry : {qMakePair("source", "saddr"), qMakePair("destination", "daddr")}) {
        const auto a = r[entry.first].toString();
        if (a != "any")
            match += QString("%1 %2 %3 ").arg(a.contains(':') ? "ip6" : "ip", entry.second, a);
    }
    const auto protocol = r["protocol"].toString();
    if (protocol == "icmp")
        match += "meta l4proto { icmp, ipv6-icmp } ";
    else if (protocol != "any")
        match += "meta l4proto " + protocol + " ";
    for (bool source : {true, false}) {
        const auto ports = firewallPorts(r, source);
        if (ports != "any")
            match += QString("%1 %2 %3 ").arg(protocol, source ? "sport" : "dport", nftPorts(ports));
    }
    return match;
}
} // namespace
QJsonObject defaultFirewallPolicy() {
    return {{"version", 2},
            {"defaults", QJsonObject{{"input", "accept"}, {"output", "accept"}, {"forward", "accept"}}},
            {"stateful", true},
            {"log_drops", false},
            {"rules", QJsonArray{}},
            {"nat", QJsonArray{}},
            {"inspection", QJsonObject{{"mode", "alert"},
                                       {"sql_injection", false},
                                       {"xss", false},
                                       {"path_traversal", false},
                                       {"blocked_domains", QJsonArray{}},
                                       {"block_fragments", false}}}};
}
QString firewallPorts(const QJsonObject &rule, bool source) {
    const auto key = source ? "source_ports" : "destination_ports";
    if (rule.contains(key))
        return rule[key].toString();
    return !source && rule["port"].toInt() > 0 ? QString::number(rule["port"].toInt()) : "any";
}
bool firewallPortMatches(const QString &ports, quint16 port) {
    if (ports == "any")
        return true;
    for (const auto &part : ports.split(',')) {
        const auto range = part.split('-');
        const int first = range[0].toInt();
        const int last = range.size() == 2 ? range[1].toInt() : first;
        if (port >= first && port <= last)
            return true;
    }
    return false;
}
QJsonObject normalizeFirewallPolicy(const QJsonValue &value, QString *error) {
    if (error)
        error->clear();
    auto p = defaultFirewallPolicy();
    QString problem;
    if (value.isArray()) {
        p["stateful"] = false;
        p["rules"] = value;
    } else if (value.isObject()) {
        const auto raw = value.toObject();
        p = merged(p, raw);
        for (const auto &key : {"defaults", "inspection"})
            if (raw.contains(key)) {
                if (!raw[key].isObject()) {
                    problem = QString("%1 должен быть объектом").arg(key);
                    break;
                }
                p[key] = merged(defaultFirewallPolicy()[key].toObject(), raw[key].toObject());
            }
    } else
        problem = "Ожидается объект политики v2 или массив правил";
    if (problem.isEmpty() && p["rules"].isArray()) {
        QJsonArray rules;
        for (const auto &v : p["rules"].toArray())
            rules.append(v.isObject() ? QJsonValue(completeRule(v.toObject())) : v);
        p["rules"] = rules;
    }
    if (problem.isEmpty() && p["nat"].isArray()) {
        QJsonArray nat;
        for (const auto &v : p["nat"].toArray())
            nat.append(v.isObject() ? QJsonValue(merged({{"interface", "any"},
                                                         {"protocol", "any"},
                                                         {"source", "any"},
                                                         {"destination", "any"},
                                                         {"port", 0},
                                                         {"to_address", ""},
                                                         {"to_port", 0},
                                                         {"enabled", true}},
                                                        v.toObject()))
                                    : v);
        p["nat"] = nat;
    }
    if (problem.isEmpty())
        problem = validateFirewallPolicy(p);
    if (!problem.isEmpty()) {
        if (error)
            *error = problem;
        return {};
    }
    return p;
}
QString validateFirewallRule(const QJsonObject &r) {
    const auto unknown = unexpected(r, {"id", "name", "direction", "source", "destination", "protocol",
                                        "port", "action", "enabled", "source_ports", "destination_ports",
                                        "in_interface", "out_interface", "log", "rate_limit", "comment"});
    if (!unknown.isEmpty())
        return unknown;
    if (!r["name"].isString() || r["name"].toString().trimmed().isEmpty() ||
        r["name"].toString().size() > 100)
        return "Укажите имя правила (до 100 символов)";
    if (!QStringList{"input", "output", "forward"}.contains(r["direction"].toString()))
        return "Некорректное направление";
    if (!QStringList{"tcp", "udp", "icmp", "any"}.contains(r["protocol"].toString()))
        return "Некорректный протокол";
    if (!QStringList{"drop", "accept", "reject"}.contains(r["action"].toString()))
        return "Некорректное действие";
    const auto src = r["source"].toString(), dst = r["destination"].toString();
    if (!address(src) || !address(dst))
        return "Нужен IP, CIDR или any";
    if (src != "any" && dst != "any" &&
        QHostAddress(src.section('/', 0, 0)).protocol() != QHostAddress(dst.section('/', 0, 0)).protocol())
        return "Адреса должны быть одной версии IP";
    if (r.contains("port") && !integer(r["port"], 0, 65535))
        return "Порт: 0 (любой) или целое число 1–65535";
    const auto sport = firewallPorts(r, true), dport = firewallPorts(r, false);
    if (!portsValid(sport) || !portsValid(dport))
        return "Порты: any или список 80,443,8000-8080 без пробелов";
    if ((sport != "any" || dport != "any") && r["protocol"] != "tcp" && r["protocol"] != "udp")
        return "Порты доступны только для TCP/UDP";
    for (const auto &key : {"enabled", "log"})
        if (r.contains(key) && !r[key].isBool())
            return QString("%1 должен быть true или false").arg(key);
    for (const auto &key : {"in_interface", "out_interface"})
        if (r.contains(key) && !iface(r[key].toString()))
            return "Интерфейс: any или системное имя до 15 символов";
    if ((r["direction"] == "input" && r["out_interface"].toString("any") != "any") ||
        (r["direction"] == "output" && r["in_interface"].toString("any") != "any"))
        return "Входящий поток не имеет out_interface, исходящий — in_interface";
    if (r.contains("rate_limit") && !integer(r["rate_limit"], 0, 1000000))
        return "Ограничение: целое число 0–1000000 пакетов/с";
    if (r["rate_limit"].toInt() && r["action"] != "accept")
        return "Ограничение скорости применяется только к accept (превышение блокируется)";
    if (r.contains("comment") && (!r["comment"].isString() || r["comment"].toString().size() > 500))
        return "Комментарий: до 500 символов";
    return {};
}
QString validateFirewallPolicy(const QJsonObject &p) {
    const auto unknown =
        unexpected(p, {"version", "defaults", "stateful", "log_drops", "rules", "nat", "inspection"});
    if (!unknown.isEmpty())
        return unknown;
    const auto defaultsError = unexpected(p["defaults"].toObject(), {"input", "output", "forward"});
    if (!defaultsError.isEmpty())
        return defaultsError;
    const auto inspectionError =
        unexpected(p["inspection"].toObject(),
                   {"mode", "sql_injection", "xss", "path_traversal", "blocked_domains", "block_fragments"});
    if (!inspectionError.isEmpty())
        return inspectionError;
    if (!integer(p["version"], 2, 2))
        return "Поддерживается только version: 2";
    if (!p["defaults"].isObject())
        return "defaults должен быть объектом";
    for (const auto &direction : {"input", "output", "forward"})
        if (!QStringList{"accept", "drop"}.contains(p["defaults"].toObject()[direction].toString()))
            return "Политика по умолчанию: accept или drop для каждого направления";
    if (!p["stateful"].isBool() || !p["log_drops"].isBool())
        return "stateful и log_drops должны быть true или false";
    if (!p["rules"].isArray() || p["rules"].toArray().size() > 1000)
        return "rules: массив, максимум 1000 правил";
    int index = 0;
    for (const auto &v : p["rules"].toArray()) {
        ++index;
        const auto error = v.isObject() ? validateFirewallRule(v.toObject()) : QString("Нужен объект");
        if (!error.isEmpty())
            return QString("Правило %1: %2").arg(index).arg(error);
    }
    if (!p["nat"].isArray() || p["nat"].toArray().size() > 256)
        return "nat: массив, максимум 256 правил";
    index = 0;
    for (const auto &v : p["nat"].toArray()) {
        ++index;
        const auto error = v.isObject() ? validateNat(v.toObject()) : QString("Нужен объект");
        if (!error.isEmpty())
            return QString("NAT %1: %2").arg(index).arg(error);
    }
    if (!p["inspection"].isObject())
        return "inspection должен быть объектом";
    const auto inspection = p["inspection"].toObject();
    if (!QStringList{"alert", "block"}.contains(inspection["mode"].toString()))
        return "Режим DPI: alert или block";
    for (const auto &key : {"sql_injection", "xss", "path_traversal", "block_fragments"})
        if (!inspection[key].isBool())
            return QString("inspection.%1 должен быть true или false").arg(key);
    if (!inspection["blocked_domains"].isArray() || inspection["blocked_domains"].toArray().size() > 256)
        return "Максимум 256 доменов";
    static const QRegularExpression domain("^(?:\\*\\.)?[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.["
                                           "a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$");
    for (const auto &v : inspection["blocked_domains"].toArray())
        if (!v.isString() || v.toString().size() > 253 || !domain.match(v.toString()).hasMatch())
            return "Домен: имя ASCII/punycode, например example.org или *.example.org";
    return {};
}
QString validateNftPolicy(const QJsonObject &p) {
    const auto error = validateFirewallPolicy(p);
    if (!error.isEmpty())
        return error;
    if (inspectionActive(p))
        return "Linux nftables не выполняет DPI: используйте профиль DPDK для HTTP/доменов/фрагментов";
    return {};
}
QString validateDpdkPolicy(const QJsonObject &p) {
    const auto error = validateFirewallPolicy(p);
    if (!error.isEmpty())
        return error;
    if (p["log_drops"].toBool())
        return "DPDK: журнал ядра недоступен; события сенсора поступают в SIEM";
    if (p["stateful"].toBool() || natActive(p))
        return "DPDK: conntrack/stateful и NAT не реализованы; отключите эти параметры";
    const auto defaults = p["defaults"].toObject();
    if (defaults["input"] != "accept" || defaults["output"] != "accept")
        return "DPDK: доступны только правила и политика forward";
    for (const auto &v : p["rules"].toArray()) {
        const auto r = v.toObject();
        if (!r["enabled"].toBool(true))
            continue;
        if (r["direction"] != "forward" || r["action"] == "reject" || r["rate_limit"].toInt() ||
            r["in_interface"].toString("any") != "any" || r["out_interface"].toString("any") != "any")
            return "DPDK: поддерживаются forward accept/drop и IP/порты; reject, интерфейсы и rate limit не "
                   "реализованы";
    }
    return {};
}
QString validateWindowsPolicy(const QJsonObject &p) {
    const auto error = validateFirewallPolicy(p);
    if (!error.isEmpty())
        return error;
    if (p["stateful"].toBool() || p["log_drops"].toBool() || natActive(p) || inspectionActive(p))
        return "Windows: настройка stateful, журналирования, NAT и DPI этим backend не поддерживается";
    for (const auto &direction : {"input", "output", "forward"})
        if (p["defaults"].toObject()[direction] != "accept")
            return "Windows: политика ОС по умолчанию не изменяется; используйте accept";
    for (const auto &v : p["rules"].toArray()) {
        const auto r = v.toObject();
        if (!r["enabled"].toBool(true))
            continue;
        if (r["direction"] == "forward" || r["protocol"] == "icmp" || r["action"] == "reject" ||
            r["rate_limit"].toInt() || r["log"].toBool() || r["in_interface"].toString("any") != "any" ||
            r["out_interface"].toString("any") != "any")
            return "Windows: поддерживаются input/output, TCP/UDP/any, IP и порты; forward, ICMP, reject, "
                   "интерфейсы, rate limit и log не поддерживаются";
    }
    return {};
}
QString compileNftPolicy(const QJsonObject &policy, QString *error) {
    QString problem;
    const auto p = normalizeFirewallPolicy(policy, &problem);
    if (problem.isEmpty())
        problem = validateNftPolicy(p);
    if (error)
        *error = problem;
    if (!problem.isEmpty())
        return {};
    // The whole batch is atomic. Recreate only our tables so removed chains, NAT and old
    // policies cannot survive an update. The first add is idempotent on an existing table.
    QString out =
        "add table inet sentinel_siem\ndelete table inet sentinel_siem\nadd table inet sentinel_siem\n"
        "add table ip sentinel_siem_nat\ndelete table ip sentinel_siem_nat\nadd table ip sentinel_siem_nat\n";
    for (const auto &d : {"input", "output", "forward"}) {
        const auto base = QString("add rule inet sentinel_siem %1 ").arg(d);
        out += QString("add chain inet sentinel_siem %1 { type filter hook %1 priority 10; policy %2; }\n")
                   .arg(d, p["defaults"].toObject()[d].toString());
        if (p["stateful"].toBool()) {
            if (p["log_drops"].toBool())
                out += base + "ct state invalid limit rate 10/second log prefix \"sentinel:invalid \"\n";
            out += base + "ct state invalid counter drop\n";
            out += base + "ct state established,related counter accept\n";
        }
    }
    int index = 0;
    for (const auto &v : p["rules"].toArray()) {
        ++index;
        const auto r = v.toObject();
        if (!r["enabled"].toBool(true))
            continue;
        const auto base = QString("add rule inet sentinel_siem %1 ").arg(r["direction"].toString());
        const auto match = nftMatch(r);
        const auto action = r["action"].toString();
        if (r["log"].toBool() || (p["log_drops"].toBool() && action != "accept"))
            out += base + match + QString("limit rate 10/second log prefix \"sentinel:r%1 \"\n").arg(index);
        if (r["rate_limit"].toInt())
            out += base + match +
                   QString("limit rate over %1/second burst %1 packets counter drop\n")
                       .arg(r["rate_limit"].toInt());
        out += base + match + "counter " + action + "\n";
    }
    for (const auto &d : {"input", "output", "forward"})
        if (p["log_drops"].toBool() && p["defaults"].toObject()[d] == "drop")
            out += QString("add rule inet sentinel_siem %1 limit rate 10/second log prefix "
                           "\"sentinel:default-%1 \"\n")
                       .arg(d);
    out += "add chain ip sentinel_siem_nat prerouting { type nat hook prerouting priority -100; policy "
           "accept; }\n"
           "add chain ip sentinel_siem_nat postrouting { type nat hook postrouting priority 100; policy "
           "accept; }\n";
    for (const auto &v : p["nat"].toArray()) {
        const auto r = v.toObject();
        if (!r["enabled"].toBool(true))
            continue;
        const auto type = r["type"].toString();
        QString s =
            QString("add rule ip sentinel_siem_nat %1 ").arg(type == "dnat" ? "prerouting" : "postrouting");
        if (r["interface"] != "any")
            s += QString("%1 \"%2\" ").arg(type == "dnat" ? "iifname" : "oifname", r["interface"].toString());
        for (const auto &entry : {qMakePair("source", "saddr"), qMakePair("destination", "daddr")})
            if (r[entry.first] != "any")
                s += QString("ip %1 %2 ").arg(entry.second, r[entry.first].toString());
        const auto protocol = r["protocol"].toString();
        if (protocol != "any")
            s += "meta l4proto " + protocol + " ";
        if (r["port"].toInt())
            s += QString("%1 dport %2 ").arg(protocol).arg(r["port"].toInt());
        s += "counter " + type;
        if (type != "masquerade") {
            s += " to " + r["to_address"].toString();
            if (r["to_port"].toInt())
                s += ":" + QString::number(r["to_port"].toInt());
        }
        out += s + "\n";
    }
    return out;
}
QString compileNft(const QJsonArray &rules, QString *error) {
    QString problem;
    const auto p = normalizeFirewallPolicy(rules, &problem);
    if (!problem.isEmpty()) {
        if (error)
            *error = problem;
        return {};
    }
    return compileNftPolicy(p, error);
}
QString firewallSummary(const QJsonArray &rules) {
    return compileNft(rules);
}
} // namespace siem
