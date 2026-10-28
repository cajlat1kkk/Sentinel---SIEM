#include "firewall.h"
#include <QHostAddress>
#include <QRegularExpression>
namespace siem {
static bool address(const QString &s) {
    if (s == "any")
        return true;
    if (s.contains('%') || s.contains(' ') || s.contains('\n'))
        return false;
    if (s.contains('/'))
        return QHostAddress::parseSubnet(s).second >= 0;
    return !QHostAddress(s).isNull();
}
QString validateFirewallRule(const QJsonObject &r) {
    if (r["name"].toString().trimmed().isEmpty() || r["name"].toString().size() > 100)
        return "Укажите имя правила (до 100 символов)";
    if (!QStringList{"input", "output", "forward"}.contains(r["direction"].toString()))
        return "Некорректное направление";
    if (!QStringList{"tcp", "udp", "icmp", "any"}.contains(r["protocol"].toString()))
        return "Некорректный протокол";
    if (!QStringList{"drop", "accept"}.contains(r["action"].toString()))
        return "Некорректное действие";
    auto src = r["source"].toString(), dst = r["destination"].toString();
    if (!address(src) || !address(dst))
        return "Нужен IP, CIDR или any";
    if (src != "any" && dst != "any" &&
        QHostAddress(src.section('/', 0, 0)).protocol() != QHostAddress(dst.section('/', 0, 0)).protocol())
        return "Адреса должны быть одной версии IP";
    auto port = r["port"].toDouble(-1);
    if (port < 0 || port > 65535 || port != int(port))
        return "Порт: 0 (любой) или 1–65535";
    if (port > 0 && r["protocol"] != "tcp" && r["protocol"] != "udp")
        return "Порты доступны только для TCP/UDP";
    return {};
}
QString compileNft(const QJsonArray &rules, QString *error) {
    if (rules.size() > 1000) {
        *error = "Максимум 1000 правил";
        return {};
    }
    QString out = "add table inet sentinel_siem\nflush table inet sentinel_siem\n";
    for (auto d : {"input", "output", "forward"})
        out +=
            QString("add chain inet sentinel_siem %1 { type filter hook %1 priority 10; policy accept; }\n")
                .arg(d);
    for (const auto &v : rules) {
        auto r = v.toObject();
        auto e = validateFirewallRule(r);
        if (!e.isEmpty()) {
            *error = e;
            return {};
        }
        if (!r["enabled"].toBool(true))
            continue;
        QString s = QString("add rule inet sentinel_siem %1 ").arg(r["direction"].toString());
        auto src = r["source"].toString(), dst = r["destination"].toString();
        if (src != "any")
            s += QString("%1 saddr %2 ").arg(src.contains(':') ? "ip6" : "ip", src);
        if (dst != "any")
            s += QString("%1 daddr %2 ").arg(dst.contains(':') ? "ip6" : "ip", dst);
        auto proto = r["protocol"].toString();
        if (proto == "icmp")
            s += "meta l4proto { icmp, ipv6-icmp } ";
        else if (proto != "any")
            s += "meta l4proto " + proto + " ";
        if (r["port"].toInt() > 0)
            s += QString("%1 dport %2 ").arg(proto).arg(r["port"].toInt());
        s += "counter " + r["action"].toString() + "\n";
        out += s;
    }
    return out;
}
QString firewallSummary(const QJsonArray &rules) {
    QString error;
    return compileNft(rules, &error);
}
} // namespace siem
