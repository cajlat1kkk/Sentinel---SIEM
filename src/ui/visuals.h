#pragma once
#include <QWidget>

namespace siem {
class GaugeWidget : public QWidget {
  public:
    explicit GaugeWidget(QWidget *parent = nullptr);
    void setValues(qint64 total, qint64 high);
    void setTheme(bool lavender);
    void setNightMode(bool night);

  protected:
    void paintEvent(QPaintEvent *) override;

  private:
    qint64 total_ = 0, high_ = 0;
    bool lavender_ = false;
    bool night_ = false;
};

class NetworkMapWidget : public QWidget {
  public:
    explicit NetworkMapWidget(QWidget *parent = nullptr);
    void setNodeCount(int count);
    void setTheme(bool lavender);
    void setNightMode(bool night);

  protected:
    void paintEvent(QPaintEvent *) override;

  private:
    int count_ = 0;
    bool lavender_ = false;
    bool night_ = false;
};
} // namespace siem
