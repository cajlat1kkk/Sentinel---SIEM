#include "visuals.h"
#include <QLocale>
#include <QPainter>
#include <QPainterPath>
#include <cmath>
#include <numbers>

namespace siem {
GaugeWidget::GaugeWidget(QWidget *parent) : QWidget(parent) {
    setMinimumSize(150, 136);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    setAccessibleName("Доля событий высокого и критического приоритета");
}
void GaugeWidget::setValues(qint64 total, qint64 high) {
    total_ = qMax(qint64(0), total);
    high_ = qBound(qint64(0), high, total_);
    setToolTip(QString("Высокий и критический приоритет: %1 из %2 событий")
                   .arg(QLocale().toString(high_), QLocale().toString(total_)));
    update();
}
void GaugeWidget::setTheme(bool lavender) {
    lavender_ = lavender;
    update();
}
void GaugeWidget::setNightMode(bool night) {
    night_ = night;
    update();
}
void GaugeWidget::paintEvent(QPaintEvent *) {
    if (width() < 40 || height() < 40)
        return;
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    const double thickness = qBound(12.0, width() / 13.0, 24.0);
    const double radius = qMin((width() - thickness - 20) / 2.0, height() - 46.0 - thickness / 2);
    if (radius <= 0)
        return;
    const QPointF center(width() / 2.0, height() - 39.0);
    const QRectF arc(center.x() - radius, center.y() - radius, radius * 2, radius * 2);
    const auto ratio = total_ ? double(high_) / double(total_) : 0.0;
    const QColor accent(night_ ? "#c1a0ed" : lavender_ ? "#aa96d6" : "#ef8b58");
    p.setPen(QPen(QColor(night_ ? "#343c50" : "#f1eff3"), thickness,
                  Qt::SolidLine, Qt::FlatCap));
    p.drawArc(arc, 0, 180 * 16);
    if (ratio > 0) {
        QLinearGradient fill(arc.topLeft(), arc.topRight());
        fill.setColorAt(0, QColor(night_ ? "#78679e" : lavender_ ? "#d7c9f0" : "#f9c4a8"));
        fill.setColorAt(1, accent);
        p.setPen(QPen(QBrush(fill), thickness, Qt::SolidLine, Qt::FlatCap));
        p.drawArc(arc, 180 * 16, -qRound(ratio * 180 * 16));
    }
    if (total_ > 0) {
        const double angle = std::numbers::pi * (1 - ratio);
        QPointF tip(center.x() + radius * std::cos(angle), center.y() - radius * std::sin(angle));
        p.setPen(QPen(QColor(night_ ? "#1e2431" : "#ffffff"), 2));
        p.setBrush(QColor(night_ ? "#eadbff" : "#353139"));
        p.drawEllipse(tip, 4, 4);
    }
    auto font = p.font();
    font.setPixelSize(qBound(24, width() / 8, 39));
    font.setWeight(QFont::Medium);
    p.setFont(font);
    p.setPen(QColor(night_ ? "#e8edf6" : "#2b292f"));
    const auto text =
        total_ ? QLocale().toString(ratio * 100, 'f', ratio > 0 && ratio < 0.01 ? 2 : 1) + "%" : QString("—");
    p.drawText(QRectF(0, center.y() - 51, width(), 48), Qt::AlignCenter, text);
    font.setPixelSize(10);
    font.setWeight(QFont::Normal);
    p.setFont(font);
    p.setPen(QColor(night_ ? "#acb8ce" : "#99939e"));
    p.drawText(QRectF(0, center.y() + 10, width(), 20), Qt::AlignCenter,
               total_ ? "высокий приоритет" : "пока нет событий");
}
NetworkMapWidget::NetworkMapWidget(QWidget *parent) : QWidget(parent) {
    setMinimumSize(130, 120);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    setAccessibleName("Узлы в инвентаризации");
}
void NetworkMapWidget::setNodeCount(int count) {
    count_ = qMax(0, count);
    setAccessibleDescription(QString("Учтено узлов: %1. Схематическая иллюстрация сети.").arg(count_));
    setToolTip(QString("В инвентаризации: %1 узлов. Схематическая иллюстрация сети.").arg(count_));
    update();
}
void NetworkMapWidget::setTheme(bool lavender) {
    lavender_ = lavender;
    update();
}
void NetworkMapWidget::setNightMode(bool night) {
    night_ = night;
    update();
}
void NetworkMapWidget::paintEvent(QPaintEvent *) {
    if (width() < 20 || height() < 20)
        return;
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    const double w = width(), h = height();
    const QColor accent(night_ ? "#b89be4" : lavender_ ? "#a797ce" : "#ed9569");
    const QPointF hub(w * 0.59, h * 0.38);
    const QVector<QPointF> nodes = {{w * 0.12, h * 0.23},
                                    {w * 0.22, h * 0.60},
                                    {w * 0.86, h * 0.14},
                                    {w * 0.93, h * 0.64},
                                    {w * 0.43, h * 0.82}};
    p.setPen(QPen(QColor(night_ ? "#3a4359" : "#f0edf2"), 2));
    for (const auto &node : nodes) {
        QPainterPath connection;
        connection.moveTo(hub);
        const double middle = (hub.x() + node.x()) / 2;
        connection.cubicTo(QPointF(middle, hub.y()), QPointF(middle, node.y()), node);
        p.drawPath(connection);
    }
    p.setPen(QPen(QColor(night_ ? "#2d3548" : "#f6f4f7"), 1));
    p.drawLine(QPointF(w * 0.25, 0), QPointF(w * 0.25, h));
    p.drawLine(QPointF(w * 0.8, 0), QPointF(w * 0.8, h));
    p.drawLine(QPointF(0, h * 0.55), QPointF(w, h * 0.55));
    for (const auto &node : nodes) {
        p.setPen(QPen(QColor(night_ ? "#59637d" : "#e9e5ed"), 1));
        p.setBrush(QColor(night_ ? "#2d364b" : "#f8f7fa"));
        p.drawEllipse(node, 6, 6);
        p.setPen(Qt::NoPen);
        p.setBrush(QColor(night_ ? "#a0acc5" : "#ccc5d3"));
        p.drawEllipse(node, 2, 2);
    }
    p.setPen(Qt::NoPen);
    p.setBrush(QColor(night_ ? "#3a3050" : lavender_ ? "#eee8f7" : "#fcece3"));
    p.drawEllipse(hub, 28, 28);
    p.setBrush(accent);
    p.drawEllipse(hub, 18, 18);
    p.setPen(QPen(QColor(night_ ? "#281e3c" : "#ffffff"), 1.4,
                  Qt::SolidLine, Qt::RoundCap));
    const QRectF chip(hub.x() - 6, hub.y() - 7, 12, 14);
    p.setBrush(Qt::NoBrush);
    p.drawRoundedRect(chip, 2, 2);
    p.drawLine(QPointF(hub.x() - 3, hub.y() - 2), QPointF(hub.x() + 3, hub.y() - 2));
    p.drawLine(QPointF(hub.x() - 3, hub.y() + 3), QPointF(hub.x() + 1, hub.y() + 3));
}
} // namespace siem
