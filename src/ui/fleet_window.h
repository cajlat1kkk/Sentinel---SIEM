#pragma once
#include "fleet/transport.h"
#include <QComboBox>
#include <QLabel>
#include <QLineEdit>
#include <QMainWindow>
#include <QPushButton>
#include <QTabWidget>
#include <QTableWidget>

namespace siem {
class FleetWindow final : public QMainWindow {
    Q_OBJECT
  public:
    explicit FleetWindow(const QJsonObject &connection);
    bool authenticated() const {
        return authenticated_;
    }

  private:
    fleet::RpcClient client_;
    QTabWidget *tabs_;
    QLabel *status_, *identity_, *metrics_;
    QLineEdit *search_;
    QComboBox *group_;
    QList<QTableWidget *> tables_;
    QList<QPushButton *> adminActions_;
    QTimer refresh_, debounce_;
    QJsonObject policy_;
    QString role_;
    bool authenticated_ = false;
    int offset_ = 0;
    void request(const QString &method, const QJsonObject &params, fleet::RpcClient::Callback callback = {});
    void refresh();
    void fill(QTableWidget *table, const QJsonArray &rows, const QStringList &keys,
              const QStringList &labels);
    QJsonObject selected() const;
    void enroll();
    void assignGroup();
    void editPolicy();
    void editRule();
    void incident();
    void exportTable();
};
} // namespace siem
