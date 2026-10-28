#include "packet.h"
#include <QHostAddress>
#include <QUrl>
namespace siem {
static quint16 u16(const QByteArray &b, int i) {
    return (quint8(b[i]) << 8) | quint8(b[i + 1]);
}
Packet inspectPacket(const QByteArray &b) {
    Packet p;
    if (b.size() < 14)
        return p;
    int offset = 14;
    quint16 type = u16(b, 12);
    for (int n = 0; n < 2 && (type == 0x8100 || type == 0x88a8); ++n) {
        if (b.size() < offset + 4)
            return p;
        type = u16(b, offset + 2);
        offset += 4;
    }
    int transport = 0, end = 0;
    quint8 proto = 0;
    if (type == 0x0800) {
        if (b.size() < offset + 20 || (quint8(b[offset]) >> 4) != 4)
            return p;
        int ihl = (quint8(b[offset]) & 15) * 4;
        int size = u16(b, offset + 2);
        if (ihl < 20 || size < ihl || b.size() < offset + size)
            return p;
        auto ip = [&](int i) {
            return QString("%1.%2.%3.%4")
                .arg(quint8(b[i]))
                .arg(quint8(b[i + 1]))
                .arg(quint8(b[i + 2]))
                .arg(quint8(b[i + 3]));
        };
        p.source = ip(offset + 12);
        p.destination = ip(offset + 16);
        proto = quint8(b[offset + 9]);
        p.fragmented = (u16(b, offset + 6) & 0x3fff) != 0;
        transport = offset + ihl;
        end = offset + size;
    } else if (type == 0x86dd) {
        if (b.size() < offset + 40 || (quint8(b[offset]) >> 4) != 6)
            return p;
        int size = u16(b, offset + 4);
        if (b.size() < offset + 40 + size)
            return p;
        Q_IPV6ADDR a{}, d{};
        for (int n = 0; n < 16; ++n) {
            a[n] = quint8(b[offset + 8 + n]);
            d[n] = quint8(b[offset + 24 + n]);
        }
        p.source = QHostAddress(a).toString();
        p.destination = QHostAddress(d).toString();
        proto = quint8(b[offset + 6]);
        transport = offset + 40;
        end = transport + size;
        // IPv6 extension headers are not reassembled/decoded in this MVP.
        if (proto == 0 || proto == 43 || proto == 44 || proto == 60) {
            p.fragmented = true;
            p.valid = true;
            p.protocol = "ipv6-extension";
            return p;
        }
    } else
        return p;
    p.protocol = proto == 6 ? "tcp" : proto == 17 ? "udp" : (proto == 1 || proto == 58) ? "icmp" : "other";
    if (p.fragmented) {
        p.valid = true;
        return p;
    }
    int payload = transport;
    if (proto == 6) {
        if (end < transport + 20)
            return p;
        int len = (quint8(b[transport + 12]) >> 4) * 4;
        if (len < 20 || transport + len > end)
            return p;
        p.sourcePort = u16(b, transport);
        p.destinationPort = u16(b, transport + 2);
        payload = transport + len;
    } else if (proto == 17) {
        if (end < transport + 8)
            return p;
        int len = u16(b, transport + 4);
        if (len < 8 || transport + len > end)
            return p;
        p.sourcePort = u16(b, transport);
        p.destinationPort = u16(b, transport + 2);
        payload = transport + 8;
        end = transport + len;
    }
    p.valid = true;
    if (proto == 6 && end > payload) {
        auto raw = b.mid(payload, qMin(end - payload, 8192));
        auto decoded = QByteArray::fromPercentEncoding(raw).toLower();
        bool http = decoded.startsWith("get ") || decoded.startsWith("post ") || decoded.startsWith("put ") ||
                    decoded.startsWith("head ") || decoded.startsWith("delete ") ||
                    decoded.startsWith("patch ");
        if (http) {
            if (decoded.contains("<script") || decoded.contains("javascript:") ||
                decoded.contains("onerror="))
                p.signature = "XSS · HTTP payload";
            else if (decoded.contains("union select") || decoded.contains("union all select") ||
                     decoded.contains("' or 1=1") || decoded.contains("' or '1'='1"))
                p.signature = "SQL injection · HTTP payload";
            else if (decoded.contains("../") || decoded.contains("..\\"))
                p.signature = "Path traversal · HTTP payload";
        }
    }
    return p;
}
static bool matchesIp(const QString &ip, const QString &filter) {
    if (filter == "any")
        return true;
    if (filter.contains('/'))
        return QHostAddress(ip).isInSubnet(QHostAddress::parseSubnet(filter));
    return QHostAddress(ip) == QHostAddress(filter);
}
bool packetBlocked(const Packet &p, const QJsonArray &rules, bool blockSignatures) {
    if (blockSignatures && !p.signature.isEmpty())
        return true;
    for (auto v : rules) {
        auto r = v.toObject();
        if (!r["enabled"].toBool(true) || r["direction"] != "forward")
            continue;
        if (!matchesIp(p.source, r["source"].toString()) ||
            !matchesIp(p.destination, r["destination"].toString()))
            continue;
        if (r["protocol"] != "any" && r["protocol"].toString() != p.protocol)
            continue;
        if (r["port"].toInt() > 0 && r["port"].toInt() != p.destinationPort)
            continue;
        return r["action"] == "drop";
    }
    return false;
}
QJsonObject packetEvent(const Packet &p) {
    return {{"type", "event"},
            {"source", "DPDK"},
            {"host", p.source},
            {"src_ip", p.source},
            {"category", "network"},
            {"severity", p.signature.isEmpty() ? "info" : "high"},
            {"message", p.signature.isEmpty() ? QString("%1 %2:%3 → %4:%5")
                                                    .arg(p.protocol, p.source)
                                                    .arg(p.sourcePort)
                                                    .arg(p.destination)
                                                    .arg(p.destinationPort)
                                              : p.signature},
            {"dst_ip", p.destination},
            {"dst_port", p.destinationPort},
            {"fragmented", p.fragmented}};
}
} // namespace siem
