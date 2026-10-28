#pragma once
#include <QByteArray>
#include <QJsonArray>
#include <QJsonObject>
namespace siem {
struct Packet {
    bool valid = false;
    QString source, destination, protocol, signature;
    quint16 sourcePort = 0, destinationPort = 0;
    bool fragmented = false;
};
Packet inspectPacket(const QByteArray &frame);
bool packetBlocked(const Packet &packet, const QJsonArray &rules, bool blockSignatures);
QJsonObject packetEvent(const Packet &packet);
} // namespace siem
