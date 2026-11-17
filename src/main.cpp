#include "ui/fleet_window.h"
#include "ui/language.h"
#include "ui/setup_wizard.h"
#include "ui/theme.h"
#include "ui/window.h"
#include <QFileDialog>
#include <QApplication>
#include <QCommandLineParser>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QFile>
#include <QFontDatabase>
#include <QFileInfo>
#include <QEventLoop>
#include <QFormLayout>
#include <QHostInfo>
#include <QMessageBox>
#include <QPalette>
#include <QProcess>
#include <QSettings>
#include <QStandardPaths>
#include <QTemporaryDir>
#include <QTimer>
#include <cstdio>
#ifdef Q_OS_WIN
#include <windows.h>
#include <shellapi.h>
#endif

class Application final : public QApplication {
  public:
    using QApplication::QApplication;
    bool notify(QObject *receiver, QEvent *event) override {
        try {
            return QApplication::notify(receiver, event);
        } catch (const std::exception &e) {
            QMessageBox::critical(
                nullptr, QCoreApplication::translate("Main", "Ошибка операции"),
                QString::fromUtf8(e.what()));
            return false;
        }
    }
};

namespace {
QString uiText(const char *source) {
    return QCoreApplication::translate("Main", source);
}

QString roleKey(siem::DeploymentRole role) {
    switch (role) {
    case siem::DeploymentRole::MainServer:
        return "main";
    case siem::DeploymentRole::ManagedEndpoint:
        return "endpoint";
    case siem::DeploymentRole::OperatorConsole:
        return "operator";
    case siem::DeploymentRole::LocalConsole:
        return "local";
    }
    return {};
}

QString supportScript(const QString &name) {
    const QDir application(QCoreApplication::applicationDirPath());
    const QStringList candidates{
        application.filePath("../libexec/sentinel-siem/" + name),
        application.filePath("../lib/sentinel-siem/" + name),
        application.filePath("../share/doc/sentinel-siem/scripts/" + name),
    };
    for (const auto &candidate : candidates) {
        const QFileInfo info(candidate);
        if (info.isFile() && info.isReadable())
            return info.canonicalFilePath();
    }
    return {};
}

bool installService(const siem::DeploymentSetup &setup,
                    const siem::DeploymentSetupResult &result, QString *error) {
    const bool server = result.role == siem::DeploymentRole::MainServer;
    const auto role = server ? QStringLiteral("server") : QStringLiteral("agent");
    const auto configuration = server ? result.serverConfiguration : result.agentConfiguration;
#ifdef Q_OS_WIN
    const auto script = supportScript("install-service.ps1");
    if (script.isEmpty()) {
        *error = uiText(QT_TRANSLATE_NOOP("Main", "Не найден привилегированный установщик службы Windows."));
        return false;
    }
    auto quote = [](const QString &value) {
        auto native = QDir::toNativeSeparators(value);
        native.replace('"', QStringLiteral("\\\""));
        return '"' + native + '"';
    };
    QString parameters = "-NoProfile -ExecutionPolicy Bypass -File " + quote(script) +
                         " -Role " + role + " -ConfigPath " + quote(configuration);
    if (server)
        parameters += " -OperatorCertificate " + quote(setup.operatorCertificatePath) +
                      " -OperatorName Administrator -OperatorRole admin";
    SHELLEXECUTEINFOW execution{};
    execution.cbSize = sizeof(execution);
    execution.fMask = SEE_MASK_NOCLOSEPROCESS;
    execution.lpVerb = L"runas";
    execution.lpFile = L"powershell.exe";
    execution.lpParameters = reinterpret_cast<LPCWSTR>(parameters.utf16());
    execution.nShow = SW_SHOWNORMAL;
    if (!ShellExecuteExW(&execution)) {
        *error = uiText(QT_TRANSLATE_NOOP(
            "Main", "Windows отклонила или не смогла запустить установщик с повышением прав."));
        return false;
    }
    WaitForSingleObject(execution.hProcess, INFINITE);
    DWORD exitCode = 1;
    GetExitCodeProcess(execution.hProcess, &exitCode);
    CloseHandle(execution.hProcess);
    if (exitCode != 0) {
        *error = uiText(QT_TRANSLATE_NOOP("Main", "Установщик службы Windows завершился с ошибкой."));
        return false;
    }
    return true;
#else
    const auto script = supportScript("install-fleet-service.py");
    const auto python = QStandardPaths::findExecutable("python3");
    const auto pkexec = QStandardPaths::findExecutable("pkexec");
    if (script.isEmpty() || python.isEmpty() || pkexec.isEmpty()) {
        *error = uiText(QT_TRANSLATE_NOOP(
            "Main", "Для установки службы нужны пакетный helper, Python 3 и pkexec."));
        return false;
    }
    QStringList arguments{python, script, role, configuration};
    if (server)
        arguments << "--operator-certificate" << setup.operatorCertificatePath
                  << "--operator-name" << "Administrator" << "--operator-role" << "admin";
    QProcess process;
    process.setProcessChannelMode(QProcess::MergedChannels);
    process.start(pkexec, arguments);
    if (!process.waitForStarted(10000)) {
        *error = process.errorString();
        return false;
    }
    QEventLoop installerLoop;
    QObject::connect(&process, &QProcess::finished, &installerLoop, &QEventLoop::quit);
    if (process.state() != QProcess::NotRunning)
        installerLoop.exec(QEventLoop::ExcludeUserInputEvents);
    if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
        auto detail = QString::fromLocal8Bit(process.readAll()).trimmed().left(8000);
        *error = detail.isEmpty()
                     ? uiText(QT_TRANSLATE_NOOP(
                           "Main", "Привилегированный установщик службы завершился с ошибкой."))
                                 : detail;
        return false;
    }
    return true;
#endif
}
} // namespace

int main(int argc, char **argv) {
    Application app(argc, argv);
    QCoreApplication::setApplicationName("Sentinel SIEM");
    QCoreApplication::setOrganizationName("Sentinel");
    QCoreApplication::setApplicationVersion("0.3.0");
    app.setStyle("Fusion");
    QFont font(QFontDatabase::families().contains("Google Sans") ? "Google Sans"
               : QFontDatabase::families().contains("Open Sans") ? "Open Sans"
                                                                 : "Segoe UI");
    font.setPixelSize(13);
    app.setFont(font);
    QSettings settings;
    QString languageError;
    const auto languageOverride =
        siem::LanguageManager::commandLineOverride(app.arguments(), &languageError);
    if (!languageError.isEmpty()) {
        std::fprintf(stderr, "%s\n", languageError.toUtf8().constData());
        return 2;
    }
    siem::LanguageManager languageManager;
    const auto languagePreference = languageOverride.isEmpty()
                                        ? siem::LanguageManager::storedPreference(settings)
                                        : languageOverride;
    languageManager.apply(app, languagePreference);
    QCommandLineParser parser;
    parser.setApplicationDescription(uiText(QT_TRANSLATE_NOOP(
        "Main", "Sentinel SIEM — нативная консоль центра безопасности")));
    parser.addHelpOption();
    parser.addVersionOption();
    parser.addOption({"demo", uiText(QT_TRANSLATE_NOOP("Main", "Изолированный деморежим (без PostgreSQL)"))});
    parser.addOption({"connect-env", uiText(QT_TRANSLATE_NOOP(
                                         "Main", "Подключиться к PostgreSQL из SIEM_DB_* без диалога"))});
    parser.addOption({"fleet", uiText(QT_TRANSLATE_NOOP(
                                   "Main", "Подключиться к серверу управления парком ПК")),
                      "configuration.json"});
    parser.addOption({"fleet-connect", uiText(QT_TRANSLATE_NOOP(
                                           "Main", "Выбрать профиль подключения к серверу управления"))});
    parser.addOption({"setup", uiText(QT_TRANSLATE_NOOP(
                                   "Main", "Настроить роль этого компьютера и создать профили"))});
    parser.addOption(
        {"language", uiText(QT_TRANSLATE_NOOP(
                         "Main", "Язык интерфейса: system, ru_RU, en_US или установленный пакет")),
         "locale"});
    parser.addOption({"smoke-test", uiText(QT_TRANSLATE_NOOP(
                                        "Main", "Проверить все страницы и завершить"))});
    parser.addOption({"screenshot", uiText(QT_TRANSLATE_NOOP(
                                        "Main", "Сохранить снимок окна и завершить")),
                      "file"});
    parser.addOption({"theme", uiText(QT_TRANSLATE_NOOP(
                                   "Main", "Палитра интерфейса: ember, flow или night")),
                      "name"});
    parser.addOption({"no-engines", uiText(QT_TRANSLATE_NOOP(
                                        "Main", "Не подключаться к VPP и не запускать DPDK автоматически"))});
    parser.addOption({"page",
                      uiText(QT_TRANSLATE_NOOP(
                          "Main", "Открыть раздел: overview, alerts, incidents, events, assets, ngfw, "
                                  "antivirus, network, reports, settings")),
                      "name", "overview"});
    parser.process(app);
    qApp->setProperty("enginesDisabled", parser.isSet("no-engines"));
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
        QString automaticFleetProfile;
        const bool explicitMode = demo || parser.isSet("connect-env") || parser.isSet("fleet") ||
                                  parser.isSet("fleet-connect") || parser.isSet("smoke-test") ||
                                  parser.isSet("screenshot");
        const bool setupMissing = !settings.value("deployment/setupComplete", false).toBool();
        if (parser.isSet("setup") || (!explicitMode && setupMissing)) {
            siem::SetupWizard wizard(nullptr, languageManager.state().requestedLocale);
            if (wizard.exec() != QDialog::Accepted)
                return 0;
            const auto setup = wizard.deploymentSetup();
            const auto result = wizard.setupResult();
            siem::LanguageManager::storePreference(settings, result.language);
            languageManager.apply(app, result.language);
            settings.setValue("deployment/setupComplete", true);
            settings.setValue("deployment/role", roleKey(result.role));
            settings.setValue("deployment/profile", result.primaryConfiguration);
            if (result.role == siem::DeploymentRole::LocalConsole) {
                settings.setValue("db/host", setup.databaseHost);
                settings.setValue("db/port", setup.databasePort);
                settings.setValue("db/name", setup.databaseName);
                settings.setValue("db/user", setup.databaseUser);
            }
            bool serviceInstalled = !result.serviceInstallationRequired;
            if (result.serviceInstallationRequired) {
                const auto answer = QMessageBox::question(
                    nullptr, uiText(QT_TRANSLATE_NOOP("Main", "Установка службы Sentinel")),
                    uiText(QT_TRANSLATE_NOOP(
                        "Main", "Профиль готов. Проверить его и установить фоновую службу сейчас? "
                                "Операционная система запросит права администратора.")),
                    QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes);
                if (answer == QMessageBox::Yes) {
                    QString installError;
                    QApplication::setOverrideCursor(Qt::WaitCursor);
                    serviceInstalled = installService(setup, result, &installError);
                    QApplication::restoreOverrideCursor();
                    if (!serviceInstalled)
                        QMessageBox::critical(
                            nullptr,
                            uiText(QT_TRANSLATE_NOOP("Main", "Не удалось установить службу")),
                            installError);
                    else
                        QMessageBox::information(
                            nullptr, uiText(QT_TRANSLATE_NOOP("Main", "Sentinel настроен")),
                            uiText(QT_TRANSLATE_NOOP(
                                "Main", "Служба проверена, установлена и запущена.")));
                }
            }
            settings.setValue("deployment/serviceConfigured", serviceInstalled);
            settings.sync();
            if (result.role == siem::DeploymentRole::ManagedEndpoint)
                return serviceInstalled ? 0 : 1;
            if (result.role == siem::DeploymentRole::MainServer ||
                result.role == siem::DeploymentRole::OperatorConsole)
                automaticFleetProfile = result.consoleConfiguration;
        } else if (!explicitMode && settings.value("deployment/setupComplete").toBool()) {
            const auto role = settings.value("deployment/role").toString();
            const auto profile = settings.value("deployment/profile").toString();
            if ((role == "main" || role == "operator") && QFileInfo::exists(profile))
                automaticFleetProfile = profile;
            else if (role == "endpoint") {
                const bool configured =
                    settings.value("deployment/serviceConfigured", false).toBool();
                QMessageBox::information(
                    nullptr,
                    uiText(QT_TRANSLATE_NOOP("Main", "Управляемый компьютер Sentinel")),
                    configured
                        ? uiText(QT_TRANSLATE_NOOP(
                              "Main", "Агент Sentinel работает как фоновая служба. Для перенастройки "
                                      "откройте «Настройка Sentinel»."))
                        : uiText(QT_TRANSLATE_NOOP(
                              "Main", "Профиль агента создан, но установка службы не подтверждена. "
                                      "Запустите настройку Sentinel повторно.")));
                return configured ? 0 : 1;
            }
        }
        if (parser.isSet("fleet") || parser.isSet("fleet-connect") ||
            !automaticFleetProfile.isEmpty()) {
            auto path = parser.isSet("fleet") ? parser.value("fleet") : automaticFleetProfile;
            if (path.isEmpty())
                path = QFileDialog::getOpenFileName(
                    nullptr,
                    uiText(QT_TRANSLATE_NOOP(
                        "Main", "Профиль подключения к серверу Sentinel")),
                    {}, "JSON (*.json)");
            if (path.isEmpty())
                return 0;
            siem::FleetWindow window(siem::fleet::readObject(path));
            window.show();
            if (parser.isSet("smoke-test"))
                QTimer::singleShot(10000, &window,
                                   [&] { app.exit(window.authenticated() ? 0 : 3); });
            return app.exec();
        }
        if (demo) {
            if (!demoDir.isValid())
                throw std::runtime_error("Cannot create demo directory");
            store = std::make_unique<siem::Store>(demoDir.filePath("demo.sqlite"));
            store->seedDemo();
        } else {
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
                auto *title = new QLabel(uiText(QT_TRANSLATE_NOOP(
                    "Main", "Подключение к PostgreSQL")));
                title->setObjectName("title");
                form->addRow(title);
                auto *help = new QLabel(uiText(QT_TRANSLATE_NOOP(
                    "Main", "Укажите адрес сервера и данные учётной записи PostgreSQL.\nСобытия "
                            "и настройки будут храниться в выбранной базе.")));
                help->setObjectName("muted");
                help->setWordWrap(true);
                form->addRow(help);
                auto *host = new QLineEdit(config.host), *name = new QLineEdit(config.name),
                     *user = new QLineEdit(config.user), *password = new QLineEdit(config.password);
                password->setEchoMode(QLineEdit::Password);
                auto *port = new QSpinBox;
                port->setRange(1, 65535);
                port->setValue(config.port);
                form->addRow(uiText(QT_TRANSLATE_NOOP("Main", "Сервер")), host);
                form->addRow(uiText(QT_TRANSLATE_NOOP("Main", "Порт")), port);
                form->addRow(uiText(QT_TRANSLATE_NOOP("Main", "База данных")), name);
                form->addRow(uiText(QT_TRANSLATE_NOOP("Main", "Пользователь")), user);
                form->addRow(uiText(QT_TRANSLATE_NOOP("Main", "Пароль")), password);
                auto *error = new QLabel;
                error->setWordWrap(true);
                error->setTextFormat(Qt::PlainText);
                error->setStyleSheet("color:#cf4d68");
                form->addRow(error);
                auto *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
                buttons->button(QDialogButtonBox::Ok)->setText(
                    uiText(QT_TRANSLATE_NOOP("Main", "Подключиться")));
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
            e.message = uiText(QT_TRANSLATE_NOOP("Main", "Консоль подключена к PostgreSQL"));
            store->ingest(e);
        }
        siem::Window window(*store, demo);
        window.show();
        window.navigate(initialPage);
        if (parser.isSet("smoke-test") || parser.isSet("screenshot"))
            QTimer::singleShot(parser.isSet("screenshot") ? 1800 : 400, &window, [&] {
                bool ok = window.smokeTest(parser.value("screenshot"), initialPage);
                app.exit(ok ? 0 : 3);
            });
        return app.exec();
    } catch (const std::exception &e) {
        if (parser.isSet("smoke-test") || parser.isSet("connect-env")) {
            std::fprintf(stderr, "%s\n", e.what());
            return 1;
        }
        QMessageBox::critical(nullptr,
                              uiText(QT_TRANSLATE_NOOP("Main", "Не удалось открыть SIEM")),
                              QString::fromUtf8(e.what()));
        return 1;
    }
}
