#pragma once
#include <QString>
#include <functional>
namespace siem::fleet {
int runService(int argc, char **argv, const QString &name, const std::function<int()> &run);
void serviceReady();
void installStopHandlers();
} // namespace siem::fleet
