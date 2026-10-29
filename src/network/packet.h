#pragma once
#include <QByteArray>
#include <QJsonArray>
#include <QJsonObject>
namespace siem {
struct Packet {
    bool valid = false;
    QString source, destination, protocol, signature, httpHost;
    quint16 etherType = 0;
    quint16 sourcePort = 0, destinationPort = 0;
    bool fragmented = false;
};
Packet inspectPacket(const QByteArray &frame);
Packet inspectPacket(const QByteArray &frame, const QJsonObject &inspection);
bool packetBlocked(const Packet &packet, const QJsonObject &policy, QString *reason = nullptr);
bool packetBlocked(const Packet &packet, const QJsonArray &rules, bool blockSignatures);
QJsonObject packetEvent(const Packet &packet);
} // namespace siem
