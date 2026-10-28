#pragma once
#include <QWidget>
namespace siem {
class Chart : public QWidget {
  public:
    explicit Chart(QWidget *parent = nullptr);
    void setValues(const QList<double> &values, const QStringList &labels);
    void setTheme(bool lavender);

  protected:
    void paintEvent(QPaintEvent *) override;
    void mouseMoveEvent(QMouseEvent *) override;
    void leaveEvent(QEvent *) override;

  private:
    QList<double> values_;
    QStringList labels_;
    int hover_ = -1;
    bool lavender_ = false;
    QRectF plotRect() const;
};
} // namespace siem
