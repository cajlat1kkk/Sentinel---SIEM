#pragma once
#include <QJsonArray>
#include <QJsonObject>
namespace siem {
QString validateFirewallRule(const QJsonObject &rule);
QString compileNft(const QJsonArray &rules, QString *error);
QString firewallSummary(const QJsonArray &rules);
} // namespace siem
