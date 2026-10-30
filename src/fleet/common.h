#pragma once
#include "core/store.h"
#include <QJsonArray>
#include <QSslConfiguration>

namespace siem::fleet {
inline constexpr int MaxFrame = 1024 * 1024;
inline constexpr int BatchSize = 50;
QString now();
QString uuid();
QString digest(const QByteArray &value);
QByteArray readFile(const QString &path, qint64 limit = MaxFrame);
QJsonObject readObject(const QString &path);
void writePrivate(const QString &path, const QByteArray &data);
void require(bool condition, const QString &message);
QSslConfiguration tlsConfiguration(const QJsonObject &config);
QString certificateId(const QString &path);
QJsonObject eventJson(const Event &event);
DatabaseConfig databaseConfig(const QJsonObject &config);
QString validateEndpointPolicy(const QJsonObject &policy);
QJsonObject defaultEndpointPolicy();
QString nativeBackend();
} // namespace siem::fleet
