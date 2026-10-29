#pragma once
#include <QJsonArray>
#include <QJsonObject>
#include <QJsonValue>
namespace siem {
QJsonObject defaultFirewallPolicy();
// Legacy arrays remain valid; their defaults are stateless and accept.
QJsonObject normalizeFirewallPolicy(const QJsonValue &value, QString *error = nullptr);
QString validateFirewallRule(const QJsonObject &rule);
QString validateFirewallPolicy(const QJsonObject &policy);
QString validateNftPolicy(const QJsonObject &policy);
QString validateDpdkPolicy(const QJsonObject &policy);
QString validateWindowsPolicy(const QJsonObject &policy);
QString compileNftPolicy(const QJsonObject &policy, QString *error = nullptr);
QString compileNft(const QJsonArray &rules, QString *error = nullptr);
QString firewallSummary(const QJsonArray &rules);
QString firewallPorts(const QJsonObject &rule, bool source);
bool firewallPortMatches(const QString &ports, quint16 port);
} // namespace siem
