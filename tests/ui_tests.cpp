#include "core/store.h"
#include "ui/ngfw_page.h"
#include "ui/theme.h"
#include <QApplication>
#include <QDialog>
#include <QDialogButtonBox>
#include <QJsonDocument>
#include <QLineEdit>
#include <QTemporaryDir>
#include <QTimer>
#include <QtTest>
using namespace siem;
class UiTests : public QObject {
    Q_OBJECT
  private slots:
    void profilesPersistIndependently() {
        QTemporaryDir dir;
        Store store(dir.filePath("profiles.sqlite"));
        NgfwPage page(store, true);
        page.resize(1200, 760);
        page.show();
        auto *backend = page.findChild<QComboBox *>("ngfwBackend");
        auto *input = page.findChild<QComboBox *>("ngfwDefaultInput");
        auto *forward = page.findChild<QComboBox *>("ngfwDefaultForward");
        auto *save = page.findChild<QPushButton *>("ngfwSave");
        QVERIFY(backend && input && forward && save);
        backend->setCurrentIndex(backend->findData("linux"));
        input->setCurrentIndex(input->findData("drop"));
        save->click();
        auto linuxPolicy =
            QJsonDocument::fromJson(
                store.scalar("SELECT value FROM meta WHERE key='ngfw.linux.draft'").toString().toUtf8())
                .object();
        QCOMPARE(linuxPolicy["defaults"].toObject()["input"].toString(), QString("drop"));
        QVERIFY(!store.scalar("SELECT value FROM meta WHERE key='ngfw.linux.applied'").isValid());
        backend->setCurrentIndex(backend->findData("dpdk"));
        QVERIFY(!input->isEnabled());
        forward->setCurrentIndex(forward->findData("drop"));
        save->click();
        QCOMPARE(page.savedDpdkPolicy()["defaults"].toObject()["forward"].toString(), QString("drop"));
        QVERIFY(!page.savedDpdkPolicy()["stateful"].toBool());
        backend->setCurrentIndex(backend->findData("linux"));
        QCOMPARE(input->currentData().toString(), QString("drop"));
        QCOMPARE(forward->currentData().toString(), QString("accept"));
        NgfwPage restored(store, true);
        QCOMPARE(restored.savedDpdkPolicy()["defaults"].toObject()["forward"].toString(), QString("drop"));
    }
    void ruleEditorSavesActualPolicy() {
        QTemporaryDir dir;
        Store store(dir.filePath("rules.sqlite"));
        NgfwPage page(store, true);
        page.resize(1200, 760);
        page.show();
        auto *backend = page.findChild<QComboBox *>("ngfwBackend");
        backend->setCurrentIndex(backend->findData("linux"));
        bool edited = false;
        QTimer::singleShot(30, &page, [&] {
            auto *dialog = qobject_cast<QDialog *>(QApplication::activeModalWidget());
            if (!dialog)
                return;
            auto *name = dialog->findChild<QLineEdit *>("ngfwRuleName");
            auto *buttons = dialog->findChild<QDialogButtonBox *>();
            if (!name || !buttons) {
                dialog->reject();
                return;
            }
            name->setText("UI: блокировать TCP");
            buttons->button(QDialogButtonBox::Save)->click();
            edited = dialog->result() == QDialog::Accepted;
            if (!edited)
                dialog->reject();
        });
        page.findChild<QPushButton *>("ngfwAddRule")->click();
        QVERIFY(edited);
        QCOMPARE(page.findChild<QTableWidget *>("ngfwRules")->rowCount(), 1);
        page.findChild<QPushButton *>("ngfwSave")->click();
        const auto policy =
            QJsonDocument::fromJson(
                store.scalar("SELECT value FROM meta WHERE key='ngfw.linux.draft'").toString().toUtf8())
                .object();
        const auto rule = policy["rules"].toArray().first().toObject();
        QCOMPARE(rule["name"].toString(), QString("UI: блокировать TCP"));
        QCOMPARE(rule["action"].toString(), QString("drop"));
        QCOMPARE(rule["protocol"].toString(), QString("tcp"));
        QVERIFY(!page.hasUnsavedChanges());
    }
    void nightThemeIncludesNativeControls() {
        const auto palette = applicationPalette("night");
        QVERIFY(palette.color(QPalette::Base).lightness() < 80);
        QVERIFY(palette.color(QPalette::Text).lightness() > 180);
        qApp->setPalette(palette);
        qApp->setStyleSheet(applicationStyle("night"));
        QVERIFY(qApp->styleSheet().contains("#surface"));
        QTemporaryDir dir;
        Store store(dir.filePath("night.sqlite"));
        NgfwPage page(store, true);
        page.show();
        QVERIFY(page.findChild<QComboBox *>("ngfwBackend")->palette().color(QPalette::Text).lightness() >
                180);
    }
};
QTEST_MAIN(UiTests)
#include "ui_tests.moc"
