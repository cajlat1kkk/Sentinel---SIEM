#pragma once
#include "common.h"

namespace siem::fleet {
class Repository final {
  public:
    explicit Repository(Store &store);
    void addOperator(const QString &fingerprint, const QString &name, const QString &role);
    QJsonObject dispatch(const QString &identity, const QString &method, const QJsonObject &params);

  private:
    Store &store_;
    void audit(const QString &identity, const QString &action, const QJsonObject &detail);
    QJsonObject enroll(const QString &identity, const QJsonObject &params);
    QJsonObject poll(const QString &identity, const QJsonObject &params);
    QJsonObject policy(const QString &group) const;
};
} // namespace siem::fleet
