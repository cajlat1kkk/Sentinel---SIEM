#pragma once
#include "core/store.h"
#include <QCheckBox>
#include <QComboBox>
#include <QJsonObject>
#include <QLabel>
#include <QPlainTextEdit>
#include <QProcess>
#include <QPushButton>
#include <QTableWidget>
#include <QTemporaryFile>
#include <QWidget>
#include <memory>

namespace siem {
class NgfwPage final : public QWidget {
    Q_OBJECT
  public:
    NgfwPage(Store &store, bool demo, QWidget *parent = nullptr);
    QJsonObject savedDpdkPolicy() const;
    bool wasAppliedHere() const;
    bool isApplying() const {
        return bool(temporary_);
    }
    bool saveChanges() {
        return saveDraft();
    }
    bool hasUnsavedChanges() const {
        return modified_;
    }
  signals:
    void notification(const QString &text, bool error);

  private:
    Store &store_;
    bool demo_, loading_ = false, modified_ = false;
    QString backend_, loadedJson_;
    QJsonObject policy_, pending_;
    QComboBox *backendBox_, *input_, *output_, *forward_, *inspectionMode_;
    QCheckBox *stateful_, *logDrops_, *sql_, *xss_, *traversal_, *fragments_;
    QPlainTextEdit *domains_;
    QTableWidget *rules_, *nat_;
    QLabel *status_, *capabilities_;
    QPushButton *apply_, *save_, *rollback_;
    QProcess process_;
    std::unique_ptr<QTemporaryFile> temporary_;
    QString key(const QString &suffix, const QString &backend = {}) const;
    QJsonObject readProfile(const QString &backend) const;
    void loadProfile(const QString &backend);
    void fill();
    void changed();
    QJsonObject collect() const;
    QString validate(const QJsonObject &policy) const;
    bool saveDraft();
    void editEntry(bool nat, bool editing);
    void removeEntry(bool nat);
    void moveRule(int delta);
    void toggleRule();
    void duplicateRule();
    void importPolicy();
    void exportPolicy();
    void preview();
    void applyPolicy(bool rollback);
    void finished(bool success, const QString &message);
    void showStatus(const QString &text, bool error = false);
};
} // namespace siem
