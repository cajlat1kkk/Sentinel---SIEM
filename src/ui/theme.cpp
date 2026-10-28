#include "theme.h"
#include <QFile>
#include <QMap>

namespace siem {
QString applicationStyle(QString name) {
    QFile base(":/style.qss");
    if (!base.open(QIODevice::ReadOnly))
        return {};
    QString style = QString::fromUtf8(base.readAll());
    if (name == "flow") {
        const QMap<QString, QString> colors = {
            {"#ef773f", "#a08bdc"}, {"#f7a86f", "#c4b4f3"}, {"#ed6939", "#9780d9"},
            {"#e9e5ed", "#e5ddf8"}, {"#e8e6ec", "#f3e8f5"}, {"#e4e8ef", "#dce7fb"},
            {"#f4f2f6", "#f2eff9"}, {"#fff2e9", "#f4efff"}, {"#fff8f0", "#f8f3ff"},
            {"#b3998c", "#a392bf"}, {"#fff9f5", "#f5efff"}, {"#dbb39b", "#c4b4e4"},
            {"#f7eee8", "#f0eaf8"}, {"#f9e9dd", "#eae1f6"}};
        for (auto it = colors.cbegin(); it != colors.cend(); ++it)
            style.replace(it.key(), it.value());
    } else if (name == "night") {
        QFile night(":/night.qss");
        if (night.open(QIODevice::ReadOnly))
            style += '\n' + QString::fromUtf8(night.readAll());
    }
    return style;
}

QPalette applicationPalette(QString name) {
    const bool night = name == "night";
    const bool flow = name == "flow";
    QPalette p;
    p.setColor(QPalette::Window, QColor(night ? "#151922" : flow ? "#f2eff9" : "#f4f2f6"));
    p.setColor(QPalette::WindowText, QColor(night ? "#e9edf5" : "#29272e"));
    p.setColor(QPalette::Base, QColor(night ? "#1c2230" : "#ffffff"));
    p.setColor(QPalette::AlternateBase, QColor(night ? "#202735" : "#fcfbfd"));
    p.setColor(QPalette::Text, QColor(night ? "#e9edf5" : "#29272e"));
    p.setColor(QPalette::Button, QColor(night ? "#262d3c" : "#ffffff"));
    p.setColor(QPalette::ButtonText, QColor(night ? "#e9edf5" : "#29272e"));
    p.setColor(QPalette::Highlight, QColor(night ? "#51436d" : flow ? "#e8dff6" : "#f6e4d7"));
    p.setColor(QPalette::HighlightedText, QColor(night ? "#ffffff" : "#473b49"));
    p.setColor(QPalette::PlaceholderText, QColor(night ? "#9da7bb" : "#958c9e"));
    p.setColor(QPalette::ToolTipBase, QColor(night ? "#343c50" : "#302a36"));
    p.setColor(QPalette::ToolTipText, QColor("#ffffff"));
    p.setColor(QPalette::Link, QColor(night ? "#c4adff" : flow ? "#8063b5" : "#ad6039"));
    p.setColor(QPalette::LinkVisited, QColor(night ? "#c0a5df" : "#8c709d"));
    p.setColor(QPalette::Light, QColor(night ? "#3d465b" : "#ffffff"));
    p.setColor(QPalette::Midlight, QColor(night ? "#30394b" : "#f1edf5"));
    p.setColor(QPalette::Mid, QColor(night ? "#30384a" : "#d8d0e1"));
    p.setColor(QPalette::Dark, QColor(night ? "#0c1018" : "#bdb4c8"));
    p.setColor(QPalette::Shadow, QColor(night ? "#080b11" : "#8d8597"));
    for (const auto role : {QPalette::WindowText, QPalette::Text, QPalette::ButtonText})
        p.setColor(QPalette::Disabled, role, QColor(night ? "#7c879c" : "#aaa2b4"));
    p.setColor(QPalette::Disabled, QPalette::Highlight, QColor(night ? "#30384a" : "#e8e3ed"));
    return p;
}
} // namespace siem
