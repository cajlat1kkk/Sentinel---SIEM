#include "ui/theme.h"
#include "ui/window.h"
#include <QApplication>
#include <QCommandLineParser>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QFile>
#include <QFontDatabase>
#include <QFormLayout>
#include <QHostInfo>
#include <QMessageBox>
#include <QPalette>
#include <QSettings>
#include <QStandardPaths>
#include <QTemporaryDir>
#include <QTimer>
#include <cstdio>

class Application final : public QApplication {
  public:
    using QApplication::QApplication;
    bool notify(QObject *receiver, QEvent *event) override {
        try {
            return QApplication::notify(receiver, event);
        } catch (const std::exception &e) {
            QMessageBox::critical(nullptr, "Ошибка операции", QString::fromUtf8(e.what()));
            return false;
        }
    }
};
int main(int argc, char **argv) {
    Application app(argc, argv);
    QCoreApplication::setApplicationName("Sentinel SIEM");
    QCoreApplication::setOrganizationName("Sentinel");
    QCoreApplication::setApplicationVersion("0.2.0");
    app.setStyle("Fusion");
    QFont font(QFontDatabase::families().contains("Google Sans") ? "Google Sans"
               : QFontDatabase::families().contains("Open Sans") ? "Open Sans"
                                                                 : "Segoe UI");
    font.setPixelSize(13);
    app.setFont(font);
    QCommandLineParser parser;
    parser.setApplicationDescription("Sentinel SIEM — нативная C++ консоль центра безопасности");
    parser.addHelpOption();
    parser.addVersionOption();
    parser.addOption({"demo", "Изолированный деморежим (без PostgreSQL)"});
    parser.addOption({"connect-env", "Подключиться к PostgreSQL из SIEM_DB_* без диалога"});
    parser.addOption({"smoke-test", "Проверить все страницы и завершить"});
    parser.addOption({"screenshot", "Сохранить снимок окна и завершить", "file"});
    parser.addOption({"theme", "Палитра интерфейса: ember, flow или night", "name"});
    parser.addOption({"page",
                      "Открыть раздел: overview, alerts, incidents, events, assets, ngfw, antivirus, "
                      "network, reports, settings",
                      "name", "overview"});
    parser.process(app);
    const QStringList pageNames{"overview", "alerts",    "incidents", "events",  "assets",
                                "ngfw",     "antivirus", "network",   "reports", "settings"};
    const int initialPage = pageNames.indexOf(parser.value("page"));
    if (initialPage < 0)
        parser.showHelp(2);
    if (parser.isSet("theme")) {
        if (!QStringList{"ember", "flow", "night"}.contains(parser.value("theme")))
            parser.showHelp(2);
        qApp->setProperty("themeOverride", parser.value("theme"));
    }
    const auto theme =
        parser.isSet("theme") ? parser.value("theme") : QSettings().value("ui/theme", "ember").toString();
    app.setPalette(siem::applicationPalette(theme));
    app.setStyleSheet(siem::applicationStyle(theme));
    const bool demo = parser.isSet("demo");
    QTemporaryDir demoDir;
    std::unique_ptr<siem::Store> store;
    try {
        if (demo) {
            if (!demoDir.isValid())
                throw std::runtime_error("Cannot create demo directory");
            store = std::make_unique<siem::Store>(demoDir.filePath("demo.sqlite"));
            store->seedDemo();
        } else {
            QSettings settings;
            siem::DatabaseConfig config;
            config.host =
                qEnvironmentVariable("SIEM_DB_HOST", settings.value("db/host", "127.0.0.1").toString());
            config.name =
                qEnvironmentVariable("SIEM_DB_NAME", settings.value("db/name", "sentinel").toString());
            config.user =
                qEnvironmentVariable("SIEM_DB_USER", settings.value("db/user", "sentinel").toString());
            config.port =
                qEnvironmentVariable("SIEM_DB_PORT", settings.value("db/port", 5432).toString()).toInt();
            config.password = qEnvironmentVariable("SIEM_DB_PASSWORD");
            if (parser.isSet("connect-env"))
                store = std::make_unique<siem::Store>(config);
            else {
                QDialog dialog;
                dialog.setWindowTitle("Sentinel SIEM · PostgreSQL");
                dialog.setMinimumWidth(510);
                auto *form = new QFormLayout(&dialog);
                form->setContentsMargins(28, 24, 28, 24);
                form->setSpacing(14);
                auto *title = new QLabel("Подключение к PostgreSQL");
                title->setObjectName("title");
                form->addRow(title);
                auto *help = new QLabel("Укажите адрес сервера и данные учётной записи PostgreSQL.\nСобытия "
                                        "и настройки будут храниться в выбранной базе.");
                help->setObjectName("muted");
                help->setWordWrap(true);
                form->addRow(help);
                auto *host = new QLineEdit(config.host), *name = new QLineEdit(config.name),
                     *user = new QLineEdit(config.user), *password = new QLineEdit(config.password);
                password->setEchoMode(QLineEdit::Password);
                auto *port = new QSpinBox;
                port->setRange(1, 65535);
                port->setValue(config.port);
                form->addRow("Сервер", host);
                form->addRow("Порт", port);
                form->addRow("База данных", name);
                form->addRow("Пользователь", user);
                form->addRow("Пароль", password);
                auto *error = new QLabel;
                error->setWordWrap(true);
                error->setTextFormat(Qt::PlainText);
                error->setStyleSheet("color:#cf4d68");
                form->addRow(error);
                auto *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
                buttons->button(QDialogButtonBox::Ok)->setText("Подключиться");
                buttons->button(QDialogButtonBox::Ok)->setObjectName("primary");
                form->addRow(buttons);
                QObject::connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
                QObject::connect(buttons, &QDialogButtonBox::accepted, &dialog, [&] {
                    config.host = host->text().trimmed();
                    config.name = name->text().trimmed();
                    config.user = user->text().trimmed();
                    config.port = port->value();
                    config.password = password->text();
                    QApplication::setOverrideCursor(Qt::WaitCursor);
                    try {
                        store = std::make_unique<siem::Store>(config);
                        QApplication::restoreOverrideCursor();
                        settings.setValue("db/host", config.host);
                        settings.setValue("db/port", config.port);
                        settings.setValue("db/name", config.name);
                        settings.setValue("db/user", config.user);
                        dialog.accept();
                    } catch (const std::exception &e) {
                        QApplication::restoreOverrideCursor();
                        error->setText(QString::fromUtf8(e.what()));
                    }
                });
                if (dialog.exec() != QDialog::Accepted)
                    return 0;
            }
            siem::Event e;
            e.source = "Sentinel";
            e.host = QHostInfo::localHostName();
            e.message = "Консоль подключена к PostgreSQL";
            store->ingest(e);
        }
        siem::Window window(*store, demo);
        window.show();
        window.navigate(initialPage);
        if (parser.isSet("smoke-test") || parser.isSet("screenshot"))
            QTimer::singleShot(400, &window, [&] {
                bool ok = window.smokeTest(parser.value("screenshot"), initialPage);
                app.exit(ok ? 0 : 3);
            });
        return app.exec();
    } catch (const std::exception &e) {
        if (parser.isSet("smoke-test") || parser.isSet("connect-env")) {
            std::fprintf(stderr, "%s\n", e.what());
            return 1;
        }
        QMessageBox::critical(nullptr, "Не удалось открыть SIEM", QString::fromUtf8(e.what()));
        return 1;
    }
}
