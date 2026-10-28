#include "chart.h"
#include <QLocale>
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QToolTip>
#include <cmath>

namespace siem {
Chart::Chart(QWidget *parent) : QWidget(parent) {
    setMinimumHeight(190);
    setMouseTracking(true);
    setAccessibleName("График полученных событий безопасности");
}
void Chart::setValues(const QList<double> &values, const QStringList &labels) {
    values_ = values;
    for (auto &value : values_)
        if (!std::isfinite(value) || value < 0)
            value = 0;
    labels_ = labels;
    if (hover_ >= values_.size())
        hover_ = -1;
    update();
}
void Chart::setTheme(bool lavender) {
    lavender_ = lavender;
    update();
}
QRectF Chart::plotRect() const {
    return QRectF(38, 32, qMax(0, width() - 52), qMax(0, height() - 66));
}
void Chart::paintEvent(QPaintEvent *) {
    const auto plot = plotRect();
    if (plot.width() <= 0 || plot.height() <= 0)
        return;
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    auto font = p.font();
    font.setPixelSize(10);
    p.setFont(font);
    double maximum = 1;
    int peak = 0;
    for (int i = 0; i < values_.size(); ++i) {
        if (values_[i] > maximum) {
            maximum = values_[i];
            peak = i;
        }
    }
    const double unit = std::pow(10.0, std::floor(std::log10(maximum)));
    maximum = qMax(4.0, std::ceil(maximum / unit) * unit);
    const QColor muted("#a3a0a6"), accent(lavender_ ? "#9b89d0" : "#ee8651");
    for (int i = 0; i <= 4; ++i) {
        double y = plot.bottom() - plot.height() * i / 4;
        p.setPen(QPen(QColor(i ? "#f1eff2" : "#e9e6eb"), 1));
        p.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y));
        p.setPen(muted);
        p.drawText(QRectF(0, y - 8, 28, 16), Qt::AlignRight | Qt::AlignVCenter,
                   QLocale().toString(maximum * i / 4, 'f', maximum < 10 ? 1 : 0));
    }
    if (values_.isEmpty()) {
        p.setPen(muted);
        p.drawText(plot, Qt::AlignCenter, "События за период ещё не поступали");
        return;
    }
    const int count = int(values_.size());
    const double slot = plot.width() / count, barWidth = qMin(36.0, slot * 0.60);
    QVector<QPointF> points;
    for (int i = 0; i < count; ++i) {
        const double x = plot.left() + slot * (i + 0.5);
        points.append(QPointF(x, plot.bottom() - values_[i] / maximum * plot.height()));
        if (i % qMax(1, (count + 5) / 6) == 0) {
            p.setPen(muted);
            p.drawText(QRectF(x - 32, plot.bottom() + 12, 64, 18), Qt::AlignCenter, labels_.value(i));
        }
    }
    const int selected = hover_ >= 0 ? hover_ : peak;
    if (!lavender_) {
        for (int i = 0; i < count; ++i) {
            if (values_[i] <= 0)
                continue;
            const auto point = points[i];
            QRectF bar(point.x() - barWidth / 2, point.y(), barWidth, plot.bottom() - point.y());
            QPainterPath shape;
            shape.addRoundedRect(bar, qMin(12.0, barWidth / 2), qMin(12.0, barWidth / 2));
            if (i == selected) {
                QLinearGradient fill(bar.topLeft(), bar.bottomRight());
                fill.setColorAt(0, QColor("#f7a071"));
                fill.setColorAt(1, QColor("#e97742"));
                p.fillPath(shape, fill);
                p.setPen(QPen(QColor(255, 255, 255, 170), 1));
                if (bar.height() > 30)
                    p.drawLine(QPointF(bar.left() + 3, bar.top() + 16),
                               QPointF(bar.left() + 3, bar.bottom() - 7));
            } else {
                p.fillPath(shape, QColor("#faf9fa"));
                p.save();
                p.setClipPath(shape);
                p.setPen(QPen(QColor("#e1dee3"), 1));
                for (double y = bar.top() - bar.width(); y < bar.bottom() + bar.width(); y += 7)
                    p.drawLine(QPointF(bar.left() - 1, y + bar.width()), QPointF(bar.right() + 1, y));
                p.restore();
            }
        }
    } else {
        QPainterPath line;
        line.moveTo(points.first());
        for (int i = 1; i < count; ++i) {
            const auto a = points[i - 1], b = points[i];
            const auto mid = (a.x() + b.x()) / 2;
            line.cubicTo(QPointF(mid, a.y()), QPointF(mid, b.y()), b);
        }
        auto area = line;
        area.lineTo(points.last().x(), plot.bottom());
        area.lineTo(points.first().x(), plot.bottom());
        area.closeSubpath();
        QLinearGradient fill(0, plot.top(), 0, plot.bottom());
        fill.setColorAt(0, QColor(191, 177, 225, 55));
        fill.setColorAt(1, QColor(218, 210, 239, 5));
        p.fillPath(area, fill);
        p.save();
        p.setClipPath(area);
        p.setPen(QPen(QColor(180, 164, 214, 70), 1));
        for (double x = plot.left(); x < plot.right(); x += 4)
            p.drawLine(QPointF(x, plot.top()), QPointF(x, plot.bottom()));
        p.restore();
        p.setPen(QPen(QColor("#8e819f"), 2, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
        p.drawPath(line);
        if (count == 1) {
            p.setBrush(accent);
            p.drawEllipse(points.first(), 3, 3);
        }
    }
    if (selected >= 0 && selected < count && values_[selected] > 0) {
        const auto point = points[selected];
        const auto value = QLocale().toString(values_[selected], 'f', 0);
        QFont bubbleFont = font;
        bubbleFont.setPixelSize(10);
        bubbleFont.setWeight(QFont::DemiBold);
        p.setFont(bubbleFont);
        const double bubbleWidth = qMax(32, QFontMetrics(bubbleFont).horizontalAdvance(value) + 18);
        QRectF bubble(point.x() - bubbleWidth / 2, qMax(1.0, point.y() - 31), bubbleWidth, 23);
        p.setPen(Qt::NoPen);
        p.setBrush(QColor("#2c2b2f"));
        p.drawRoundedRect(bubble, 11.5, 11.5);
        p.setPen(Qt::white);
        p.drawText(bubble, Qt::AlignCenter, value);
        p.setPen(QPen(Qt::white, 2));
        p.setBrush(QColor(lavender_ ? "#8e819f" : "#7e482d"));
        p.drawEllipse(QPointF(point.x(), point.y() + (lavender_ ? 0 : qMin(7.0, plot.bottom() - point.y()))),
                      3.5, 3.5);
    }
}
void Chart::mouseMoveEvent(QMouseEvent *event) {
    const auto plot = plotRect();
    if (values_.isEmpty() || plot.width() <= 0 || !plot.contains(event->position())) {
        hover_ = -1;
        QToolTip::hideText();
        update();
        return;
    }
    hover_ = qBound(0, int((event->position().x() - plot.left()) / plot.width() * values_.size()),
                    int(values_.size()) - 1);
    QToolTip::showText(event->globalPosition().toPoint(),
                       QString("%1 · %2 событий")
                           .arg(labels_.value(hover_), QLocale().toString(values_.value(hover_), 'f', 0)),
                       this);
    update();
}
void Chart::leaveEvent(QEvent *) {
    hover_ = -1;
    QToolTip::hideText();
    update();
}
} // namespace siem
