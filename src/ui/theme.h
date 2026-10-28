#pragma once
#include <QPalette>
#include <QString>

namespace siem {
// Accepted names are ember, flow and night. Unknown names use ember.
QString applicationStyle(QString name);
QPalette applicationPalette(QString name);
} // namespace siem
