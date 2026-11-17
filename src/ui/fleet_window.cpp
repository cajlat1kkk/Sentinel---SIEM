#include "fleet_window.h"
#include "language.h"
#include "maintenance_dialog.h"
#include "ngfw_page.h"
#include "theme.h"
#include <QApplication>
#include <QCheckBox>
#include <QCoreApplication>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFormLayout>
#include <QHeaderView>
#include <QInputDialog>
#include <QJsonDocument>
#include <QLocale>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QProcess>
#include <QSettings>
#include <QSpinBox>
#include <QTemporaryDir>
#include <QVBoxLayout>

namespace siem {
using namespace fleet;
FleetWindow::FleetWindow(const QJsonObject &c) : client_(c, this) {
    setWindowTitle(QCoreApplication::translate("FleetWindow", "Sentinel SIEM · Управление парком ПК"));
    resize(1360, 900);
    auto *root = new QWidget;
    root->setObjectName("surface");
    setCentralWidget(root);
    auto *layout = new QVBoxLayout(root);
    layout->setContentsMargins(28, 24, 28, 24);
    layout->setSpacing(18);
    auto *top = new QHBoxLayout;
    auto *title = new QLabel(QCoreApplication::translate("FleetWindow", "Sentinel · Центр безопасности"));
    title->setObjectName("title");
    top->addWidget(title);
    top->addStretch();
    identity_ = new QLabel(QCoreApplication::translate("FleetWindow", "Проверка подключения…"));
    top->addWidget(identity_);
    auto *languageButton = new QPushButton(QCoreApplication::translate("FleetWindow", "Язык"));
    top->addWidget(languageButton);
    auto *setupButton = new QPushButton(QCoreApplication::translate("FleetWindow", "Настройка"));
    top->addWidget(setupButton);
    auto *maintenance = new QPushButton(QLocale().language() == QLocale::English ? "Maintenance" : "Обслуживание");
    top->addWidget(maintenance);
    connect(maintenance, &QPushButton::clicked, this, [this] { MaintenanceDialog(this).exec(); });
    auto *theme = new QPushButton(QCoreApplication::translate("FleetWindow", "☾ Тема"));
    top->addWidget(theme);
    layout->addLayout(top);
    connect(theme, &QPushButton::clicked, this, [] {
        auto name = QSettings().value("ui/theme", "ember").toString() == "night" ? QString("ember")
                                                                                 : QString("night");
        QSettings().setValue("ui/theme", name);
        qApp->setPalette(applicationPalette(name));
        qApp->setStyleSheet(applicationStyle(name));
    });
    connect(languageButton, &QPushButton::clicked, this, [this] {
        QSettings settings;
        const auto options = LanguageManager::options(QLocale().name());
        QStringList labels;
        int current = 0;
        for (int i = 0; i < options.size(); ++i) {
            labels << options[i].label;
            if (options[i].preference == LanguageManager::storedPreference(settings))
                current = i;
        }
        bool accepted = false;
        const auto selected = QInputDialog::getItem(
            this, QCoreApplication::translate("FleetWindow", "Язык интерфейса"),
            QCoreApplication::translate("FleetWindow", "Язык"), labels, current, false, &accepted);
        if (!accepted)
            return;
        const auto index = labels.indexOf(selected);
        if (index < 0)
            return;
        LanguageManager::storePreference(settings, options[index].preference);
        if (QMessageBox::question(
                this, QCoreApplication::translate("FleetWindow", "Перезапуск приложения"),
                QCoreApplication::translate("FleetWindow", "Язык сохранён. Перезапустить приложение сейчас?")) !=
            QMessageBox::Yes)
            return;
        QStringList arguments;
        const auto currentArguments = QCoreApplication::arguments();
        for (int i = 1; i < currentArguments.size(); ++i) {
            if (currentArguments[i] == "--language") {
                ++i;
                continue;
            }
            if (!currentArguments[i].startsWith("--language="))
                arguments << currentArguments[i];
        }
        if (close())
            QProcess::startDetached(QCoreApplication::applicationFilePath(), arguments);
    });
    connect(setupButton, &QPushButton::clicked, this, [this] {
        if (close())
            QProcess::startDetached(QCoreApplication::applicationFilePath(), {"--setup"});
    });
    metrics_ = new QLabel(QCoreApplication::translate("FleetWindow", "Устройства • события • инциденты"));
    metrics_->setObjectName("cardTitle");
    layout->addWidget(metrics_);
    auto *toolbar = new QHBoxLayout;
    search_ = new QLineEdit;
    search_->setPlaceholderText(
        QCoreApplication::translate("FleetWindow", "Поиск событий по компьютеру или сообщению…"));
    toolbar->addWidget(search_, 1);
    auto *update = new QPushButton(QCoreApplication::translate("FleetWindow", "Обновить"));
    toolbar->addWidget(update);
    connect(update, &QPushButton::clicked, this, &FleetWindow::refresh);
    auto *exportButton = new QPushButton(QCoreApplication::translate("FleetWindow", "Экспорт CSV"));
    toolbar->addWidget(exportButton);
    connect(exportButton, &QPushButton::clicked, this, &FleetWindow::exportTable);
    layout->addLayout(toolbar);
    tabs_ = new QTabWidget;
    const QStringList names{QCoreApplication::translate("FleetWindow", "Компьютеры"),
                            QCoreApplication::translate("FleetWindow", "События"),
                            QCoreApplication::translate("FleetWindow", "Инциденты"),
                            QCoreApplication::translate("FleetWindow", "Политики"),
                            QCoreApplication::translate("FleetWindow", "Корреляция"),
                            QCoreApplication::translate("FleetWindow", "Аудит"),
                            QCoreApplication::translate("FleetWindow", "Задания"),
                            QLocale().language() == QLocale::English ? "Network radar" : "Сетевой радар",
                            QLocale().language() == QLocale::English ? "Top traffic sources" : "Источники трафика"};
    for (int n = 0; n < names.size(); ++n) {
        auto *page = new QWidget;
        auto *box = new QVBoxLayout(page);
        auto *actions = new QHBoxLayout;
        box->addLayout(actions);
        if (n == 7) {
            radarStatus_ = new QLabel;
            radarStatus_->setWordWrap(true);
            box->addWidget(radarStatus_);
        }
        if (n == 8) {
            auto *hint = new QLabel(QLocale().language() == QLocale::English
                ? "Top sources over the last 5 minutes of received flow aggregates. IP addresses are observations, not authenticated device identities."
                : "Источники за последние 5 минут приёма агрегатов потоков. IP — наблюдаемый адрес, а не подтверждённая личность компьютера.");
            hint->setWordWrap(true);
            box->addWidget(hint);
        }
        auto *table = new QTableWidget;
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setSelectionMode(QAbstractItemView::SingleSelection);
        table->setAlternatingRowColors(true);
        table->verticalHeader()->hide();
        table->horizontalHeader()->setStretchLastSection(true);
        box->addWidget(table, 1);
        tables_ << table;
        tabs_->addTab(page, names[n]);
        auto action = [&, this](const QString &text, auto callback, bool admin = true) {
            auto *button = new QPushButton(text);
            actions->addWidget(button);
            connect(button, &QPushButton::clicked, this, callback);
            if (admin) {
                button->setEnabled(false);
                adminActions_ << button;
            }
            return button;
        };
        if (n == 0) {
            action(QCoreApplication::translate("FleetWindow", "Подключить компьютер"), [this] { enroll(); });
            action(QCoreApplication::translate("FleetWindow", "Назначить группу"), [this] { assignGroup(); });
            action(QCoreApplication::translate("FleetWindow", "Проверить антивирусом"), [this] {
                auto row = selected();
                if (!row.isEmpty())
                    request("commands.scan", {{"identity", row["identity"]}});
            });
            action(QCoreApplication::translate("FleetWindow", "Отозвать доступ"), [this] {
                auto row = selected();
                if (row.isEmpty())
                    return;
                if (QMessageBox::question(
                        this, QCoreApplication::translate("FleetWindow", "Отзыв доступа"),
                        QCoreApplication::translate(
                            "FleetWindow",
                            "Отключить от сервера компьютер «%1»? Локальная защита продолжит работу.")
                            .arg(row["hostname"].toString())) == QMessageBox::Yes)
                    request("devices.revoke", {{"identity", row["identity"]}});
            });
            connect(table, &QTableWidget::cellDoubleClicked, this, [this] {
                auto row = selected();
                QDialog d(this);
                d.setWindowTitle(QCoreApplication::translate("FleetWindow", "Состояние компьютера"));
                d.resize(720, 550);
                auto *l = new QVBoxLayout(&d);
                auto *text = new QPlainTextEdit;
                text->setReadOnly(true);
                row["health"] = QJsonDocument::fromJson(row["health"].toString().toUtf8()).object();
                text->setPlainText(QString::fromUtf8(QJsonDocument(row).toJson()));
                l->addWidget(text);
                d.exec();
            });
        }
        if (n == 2)
            action(
                QCoreApplication::translate("FleetWindow", "Изменить статус"), [this] { incident(); }, false);
        if (n == 3) {
            group_ = new QComboBox;
            group_->setMinimumWidth(180);
            group_->addItem("default");
            actions->addWidget(group_);
            action(QCoreApplication::translate("FleetWindow", "Настроить политику"),
                   [this] { editPolicy(); });
            action(QCoreApplication::translate("FleetWindow", "Создать группу"), [this] {
                bool ok = false;
                auto name = QInputDialog::getText(
                    this, QCoreApplication::translate("FleetWindow", "Группа компьютеров"),
                    QCoreApplication::translate("FleetWindow", "Имя группы (латиница, цифры, - и _)"),
                    QLineEdit::Normal, {}, &ok);
                if (ok)
                    request("groups.create", {{"group", name}});
            });
            connect(group_, &QComboBox::currentTextChanged, this, [this] {
                if (tabs_->currentIndex() == 3)
                    refresh();
            });
        }
        if (n == 4)
            action(QCoreApplication::translate("FleetWindow", "Добавить правило"), [this] { editRule(); });
        actions->addStretch();
    }
    layout->addWidget(tabs_, 1);
    auto *bottom = new QHBoxLayout;
    auto *previous = new QPushButton(QCoreApplication::translate("FleetWindow", "← Предыдущие")),
         *next = new QPushButton(QCoreApplication::translate("FleetWindow", "Следующие →"));
    bottom->addWidget(previous);
    bottom->addWidget(next);
    status_ = new QLabel(QCoreApplication::translate("FleetWindow", "Подключение по защищённому каналу…"));
    status_->setTextFormat(Qt::PlainText);
    status_->setWordWrap(true);
    bottom->addWidget(status_, 1);
    layout->addLayout(bottom);
    connect(previous, &QPushButton::clicked, this, [this] {
        offset_ = qMax(0, offset_ - 50);
        refresh();
    });
    connect(next, &QPushButton::clicked, this, [this] {
        if (tables_[tabs_->currentIndex()]->rowCount() == 50)
            offset_ += 50;
        refresh();
    });
    connect(tabs_, &QTabWidget::currentChanged, this, [this] {
        offset_ = 0;
        refresh();
    });
    debounce_.setSingleShot(true);
    debounce_.setInterval(300);
    connect(search_, &QLineEdit::textChanged, this, [this] {
        offset_ = 0;
        debounce_.start();
    });
    connect(&debounce_, &QTimer::timeout, this, &FleetWindow::refresh);
    connect(&refresh_, &QTimer::timeout, this, &FleetWindow::refresh);
    refresh_.start(10000);
    QTimer::singleShot(0, this, &FleetWindow::refresh);
}
void FleetWindow::request(const QString &method, const QJsonObject &params, RpcClient::Callback callback) {
    if (client_.busy()) {
        status_->setText(
            QCoreApplication::translate("FleetWindow", "Дождитесь завершения текущего запроса."));
        return;
    }
    status_->setText(QCoreApplication::translate("FleetWindow", "Получение данных…"));
    client_.call(method, params, [this, callback](const QJsonObject &r, const QString &error) {
        status_->setText(error.isEmpty() ? QCoreApplication::translate("FleetWindow", "Обновлено: ") +
                                               QDateTime::currentDateTime().toString("HH:mm:ss")
                                         : QCoreApplication::translate("FleetWindow", "Ошибка: ") + error);
        if (callback)
            callback(r, error);
        else if (error.isEmpty())
            refresh();
    });
}
void FleetWindow::refresh() {
    if (client_.busy())
        return;
    if (!authenticated_) {
        request("session", {}, [this](const QJsonObject &r, const QString &error) {
            if (!error.isEmpty())
                return;
            authenticated_ = true;
            role_ = r["role"].toString();
            identity_->setText(r["name"].toString() + " · " +
                               (role_ == "admin" ? QCoreApplication::translate("FleetWindow", "Администратор")
                                                 : QCoreApplication::translate("FleetWindow", "Аналитик")));
            for (auto *button : adminActions_)
                button->setEnabled(role_ == "admin");
            request("overview", {}, [this](const QJsonObject &r, const QString &error) {
                if (error.isEmpty())
                    metrics_->setText(
                        QString(QCoreApplication::translate(
                                    "FleetWindow",
                                    "Компьютеры: %1   •   На связи: %2   •   События за сутки: %3  "
                                    " •   Открытые инциденты: %4"))
                            .arg(r["devices"].toInt())
                            .arg(r["online"].toInt())
                            .arg(r["events"].toDouble(), 0, 'f', 0)
                            .arg(r["incidents"].toInt()));
                refresh();
            });
        });
        return;
    }
    int tab = tabs_->currentIndex();
    const QStringList methods{"devices.list", "events.list", "incidents.list", "groups.list",
                              "rules.list",   "audit.list",  "commands.list", "radar.flows", "radar.top"};
    const QList<QStringList> keys{{"hostname", "platform", "group_name", "last_seen", "revoked", "identity"},
                                  {"time", "host", "source", "severity", "message"},
                                  {"id", "time", "host", "severity", "status", "title"},
                                  {"name", "revision"},
                                  {"name", "pattern", "threshold", "window_seconds", "severity", "enabled"},
                                  {"time", "action", "detail"},
                                  {"created", "device", "kind", "state", "result"},
                                  {"seen", "source", "reported_device", "source_port", "destination", "destination_port", "protocol", "packets", "bytes"},
                                  {"source", "bytes", "packets", "flows"}};
    const QList<QStringList> labels{{QCoreApplication::translate("FleetWindow", "Компьютер"),
                                     QCoreApplication::translate("FleetWindow", "ОС"),
                                     QCoreApplication::translate("FleetWindow", "Группа"),
                                     QCoreApplication::translate("FleetWindow", "Последняя связь"),
                                     QCoreApplication::translate("FleetWindow", "Доступ отозван"),
                                     QCoreApplication::translate("FleetWindow", "Идентификатор")},
                                    {QCoreApplication::translate("FleetWindow", "Время"),
                                     QCoreApplication::translate("FleetWindow", "Компьютер"),
                                     QCoreApplication::translate("FleetWindow", "Источник"),
                                     QCoreApplication::translate("FleetWindow", "Приоритет"),
                                     QCoreApplication::translate("FleetWindow", "Сообщение")},
                                    {"ID", QCoreApplication::translate("FleetWindow", "Время"),
                                     QCoreApplication::translate("FleetWindow", "Компьютер"),
                                     QCoreApplication::translate("FleetWindow", "Приоритет"),
                                     QCoreApplication::translate("FleetWindow", "Статус"),
                                     QCoreApplication::translate("FleetWindow", "Инцидент")},
                                    {QCoreApplication::translate("FleetWindow", "Группа"),
                                     QCoreApplication::translate("FleetWindow", "Версия политики")},
                                    {QCoreApplication::translate("FleetWindow", "Название"),
                                     QCoreApplication::translate("FleetWindow", "Условие"),
                                     QCoreApplication::translate("FleetWindow", "Порог"),
                                     QCoreApplication::translate("FleetWindow", "Окно, с"),
                                     QCoreApplication::translate("FleetWindow", "Приоритет"),
                                     QCoreApplication::translate("FleetWindow", "Включено")},
                                    {QCoreApplication::translate("FleetWindow", "Время"),
                                     QCoreApplication::translate("FleetWindow", "Действие"),
                                     QCoreApplication::translate("FleetWindow", "Подробности")},
                                    {QCoreApplication::translate("FleetWindow", "Создано"),
                                     QCoreApplication::translate("FleetWindow", "Компьютер"),
                                     QCoreApplication::translate("FleetWindow", "Задание"),
                                     QCoreApplication::translate("FleetWindow", "Статус"),
                                     QCoreApplication::translate("FleetWindow", "Результат")},
                                    QLocale().language() == QLocale::English
                                        ? QStringList{"Received", "Source IP", "Device (agent-reported IP)", "Port", "Destination IP", "Port", "IP protocol", "Packets", "Bytes"}
                                        : QStringList{"Получено", "IP источника", "ПК (IP из отчёта агента)", "Порт", "IP назначения", "Порт", "IP-протокол", "Пакеты", "Байты"},
                                    QLocale().language() == QLocale::English
                                        ? QStringList{"Source IP", "Bytes", "Packets", "Flow buckets"}
                                        : QStringList{"IP источника", "Байты", "Пакеты", "Агрегаты потоков"}};
    request(methods[tab], {{"offset", offset_}, {"limit", 50}, {"search", search_->text()}},
            [this, tab, keys, labels](const QJsonObject &r, const QString &error) {
                if (!error.isEmpty())
                    return;
                fill(tables_[tab], r["rows"].toArray(), keys[tab], labels[tab]);
                if (tab == 7) {
                    const auto s = r["status"].toObject();
                    const bool en = QLocale().language() == QLocale::English;
                    const auto age = s["last_record_age_seconds"].toInteger(-1);
                    const auto state = !s["enabled"].toBool() ? (en ? "Disabled in server configuration" : "Выключен в конфигурации сервера")
                        : !s["listening"].toBool() ? (en ? "Receiver unavailable" : "Приёмник недоступен")
                        : age < 0 ? (en ? "Waiting for IPFIX; traffic visibility is unconfirmed" : "Ожидание IPFIX; видимость трафика не подтверждена")
                        : (en ? "Receiving flow observations" : "Получены сведения о потоках");
                    radarStatus_->setText(QString(en ? "%1 · last flow: %2 s ago · decode errors: %3 · dropped: %4 · storage errors: %5\nRequires SPAN/TAP. Scan alerts appear in Events and Incidents."
                        : "%1 · возраст потока: %2 с · ошибки разбора: %3 · потери: %4 · ошибки БД: %5\nНужен SPAN/TAP. Признаки сканирования — в событиях и инцидентах.")
                        .arg(state).arg(age).arg(s["decode_errors"].toInteger()).arg(s["dropped_records"].toInteger()).arg(s["storage_errors"].toInteger()));
                }
                if (tab == 3) {
                    auto previous = group_->currentText();
                    QSignalBlocker blocker(group_);
                    group_->clear();
                    for (auto v : r["rows"].toArray())
                        group_->addItem(v.toObject()["name"].toString());
                    int index = group_->findText(previous);
                    if (index >= 0)
                        group_->setCurrentIndex(index);
                }
            });
}
void FleetWindow::fill(QTableWidget *t, const QJsonArray &rows, const QStringList &keys,
                       const QStringList &labels) {
    t->setUpdatesEnabled(false);
    t->setColumnCount(keys.size());
    t->setHorizontalHeaderLabels(labels);
    t->setRowCount(rows.size());
    for (int row = 0; row < rows.size(); ++row)
        for (int col = 0; col < keys.size(); ++col) {
            auto value = rows[row].toObject()[keys[col]];
            auto text = value.toVariant().toString();
            auto *item = new QTableWidgetItem(text);
            item->setToolTip(text);
            if (col == 0)
                item->setData(Qt::UserRole, rows[row].toObject());
            t->setItem(row, col, item);
        }
    t->resizeColumnsToContents();
    for (int i = 0; i < t->columnCount(); ++i)
        t->setColumnWidth(i, qMin(350, t->columnWidth(i)));
    t->setUpdatesEnabled(true);
}
QJsonObject FleetWindow::selected() const {
    auto *t = tables_[tabs_->currentIndex()];
    auto row = t->currentRow();
    return row >= 0 && t->item(row, 0) ? t->item(row, 0)->data(Qt::UserRole).toJsonObject() : QJsonObject{};
}
void FleetWindow::enroll() {
    QSignalBlocker pauseRefresh(refresh_);
    auto file = QFileDialog::getOpenFileName(
        this, QCoreApplication::translate("FleetWindow", "Сертификат нового компьютера"), {},
        QCoreApplication::translate("FleetWindow", "Сертификаты (*.crt *.pem *.cer)"));
    if (file.isEmpty())
        return;
    QString id;
    try {
        id = certificateId(file);
    } catch (const std::exception &e) {
        status_->setText(e.what());
        return;
    }
    bool ok = false;
    auto group = QInputDialog::getText(
        this, QCoreApplication::translate("FleetWindow", "Регистрация компьютера"),
        QCoreApplication::translate("FleetWindow", "Группа"), QLineEdit::Normal, "default", &ok);
    if (!ok)
        return;
    request(
        "enrollment.create", {{"identity", id}, {"group", group}},
        [this](const QJsonObject &r, const QString &error) {
            if (!error.isEmpty())
                return;
            auto file = QFileDialog::getSaveFileName(
                this, QCoreApplication::translate("FleetWindow", "Сохранить одноразовый код подключения"),
                "enrollment.token");
            if (file.isEmpty())
                return;
            try {
                writePrivate(file, r["token"].toString().toUtf8());
                status_->setText(QCoreApplication::translate(
                    "FleetWindow", "Код сохранён. Действует один час и только для выбранного сертификата."));
            } catch (const std::exception &e) {
                status_->setText(e.what());
            }
        });
}
void FleetWindow::assignGroup() {
    QSignalBlocker pauseRefresh(refresh_);
    auto row = selected();
    if (row.isEmpty())
        return;
    bool ok = false;
    auto name = QInputDialog::getText(this, QCoreApplication::translate("FleetWindow", "Назначить группу"),
                                      QCoreApplication::translate("FleetWindow", "Имя существующей группы"),
                                      QLineEdit::Normal, row["group_name"].toString(), &ok);
    if (ok)
        request("devices.group", {{"identity", row["identity"]}, {"group", name}});
}
void FleetWindow::editPolicy() {
    request(
        "policies.get", {{"group", group_->currentText()}},
        [this](const QJsonObject &response, const QString &error) {
            if (!error.isEmpty())
                return;
            QSignalBlocker pauseRefresh(refresh_);
            QDialog dialog(this);
            dialog.setWindowTitle(QCoreApplication::translate("FleetWindow", "Политика группы «%1»")
                                      .arg(response["group"].toString()));
            dialog.resize(700, 600);
            auto value = response["policy"].toObject();
            auto *layout = new QFormLayout(&dialog);
            auto *help = new QLabel(QCoreApplication::translate(
                "FleetWindow", "Политика применяется агентами выбранной группы. Для первого "
                               "развёртывания используйте небольшую пилотную группу."));
            help->setWordWrap(true);
            layout->addRow(help);
            auto *firewall =
                new QPushButton(QCoreApplication::translate("FleetWindow", "Настроить firewall / NGFW…"));
            layout->addRow(firewall);
            auto av = value["antivirus"].toObject();
            auto *enabled =
                new QCheckBox(QCoreApplication::translate("FleetWindow", "Проверять по расписанию"));
            enabled->setChecked(av["enabled"].toBool());
            layout->addRow(enabled);
            auto *paths = new QPlainTextEdit, *exclusions = new QPlainTextEdit;
            QStringList list;
            for (auto v : av["paths"].toArray())
                list << v.toString();
            paths->setPlainText(list.join('\n'));
            list.clear();
            for (auto v : av["exclusions"].toArray())
                list << v.toString();
            exclusions->setPlainText(list.join('\n'));
            layout->addRow(QCoreApplication::translate("FleetWindow", "Папки для проверки\n(одна на строку)"),
                           paths);
            layout->addRow(QCoreApplication::translate("FleetWindow", "Исключения\n(один путь на строку)"),
                           exclusions);
            auto *interval = new QSpinBox;
            interval->setRange(5, 43200);
            interval->setValue(av["interval_minutes"].toInt(1440));
            layout->addRow(QCoreApplication::translate("FleetWindow", "Интервал, минут"), interval);
            connect(firewall, &QPushButton::clicked, &dialog, [&] {
                QTemporaryDir temporary;
                Store drafts(temporary.filePath("draft.sqlite"));
                const auto fw = value["firewall"].toObject();
                for (auto it = fw.begin(); it != fw.end(); ++it)
                    drafts.exec("INSERT INTO meta(key,value) VALUES(?,?)",
                                {"ngfw." + it.key() + ".draft",
                                 QString::fromUtf8(
                                     QJsonDocument(it.value().toObject()).toJson(QJsonDocument::Compact))});
                QDialog editor(&dialog);
                editor.setWindowTitle(QCoreApplication::translate("FleetWindow", "Firewall группы"));
                editor.resize(1150, 800);
                auto *box = new QVBoxLayout(&editor);
                auto *page = new NgfwPage(drafts, true);
                page->setPolicyEditorOnly();
                box->addWidget(page);
                auto *buttons = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel);
                box->addWidget(buttons);
                connect(buttons, &QDialogButtonBox::accepted, &editor, [&] {
                    if (page->saveChanges())
                        editor.accept();
                });
                connect(buttons, &QDialogButtonBox::rejected, &editor, &QDialog::reject);
                if (editor.exec() == QDialog::Accepted) {
                    QJsonObject profiles;
                    for (const auto &backend : {"linux", "windows", "dpdk"}) {
                        auto text = drafts
                                        .scalar("SELECT value FROM meta WHERE key=?",
                                                {"ngfw." + QString(backend) + ".draft"})
                                        .toString();
                        if (!text.isEmpty())
                            profiles[backend] = QJsonDocument::fromJson(text.toUtf8()).object();
                    }
                    value["firewall"] = profiles;
                }
            });
            auto *buttons = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel);
            layout->addRow(buttons);
            connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
            connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
            if (dialog.exec() != QDialog::Accepted)
                return;
            QJsonArray dirs, excluded;
            for (auto line : paths->toPlainText().split('\n'))
                if (!line.trimmed().isEmpty())
                    dirs.append(line.trimmed());
            for (auto line : exclusions->toPlainText().split('\n'))
                if (!line.trimmed().isEmpty())
                    excluded.append(line.trimmed());
            value["antivirus"] = QJsonObject{{"enabled", enabled->isChecked()},
                                             {"paths", dirs},
                                             {"exclusions", excluded},
                                             {"interval_minutes", interval->value()}};
            request("policies.set", {{"group", response["group"]},
                                     {"expected_revision", response["revision"]},
                                     {"policy", value}});
        });
}
void FleetWindow::incident() {
    QSignalBlocker pauseRefresh(refresh_);
    auto row = selected();
    if (row.isEmpty())
        return;
    bool ok = false;
    const QStringList labels{QCoreApplication::translate("FleetWindow", "Открыт"),
                             QCoreApplication::translate("FleetWindow", "Расследование"),
                             QCoreApplication::translate("FleetWindow", "Решён"),
                             QCoreApplication::translate("FleetWindow", "Ложное срабатывание")},
        values{"open", "investigating", "resolved", "false_positive"};
    auto status = QInputDialog::getItem(this, QCoreApplication::translate("FleetWindow", "Инцидент"),
                                        QCoreApplication::translate("FleetWindow", "Новый статус"), labels, 0,
                                        false, &ok);
    if (!ok)
        return;
    auto note = QInputDialog::getMultiLineText(this, QCoreApplication::translate("FleetWindow", "Инцидент"),
                                               QCoreApplication::translate("FleetWindow", "Комментарий"),
                                               row["note"].toString(), &ok);
    if (ok)
        request("incidents.update",
                {{"id", row["id"]}, {"status", values[labels.indexOf(status)]}, {"note", note}});
}
void FleetWindow::editRule() {
    QSignalBlocker pauseRefresh(refresh_);
    QDialog d(this);
    d.setWindowTitle(QCoreApplication::translate("FleetWindow", "Новое правило корреляции"));
    auto *form = new QFormLayout(&d);
    auto *name = new QLineEdit, *pattern = new QLineEdit;
    auto *count = new QSpinBox, *window = new QSpinBox;
    auto *severity = new QComboBox;
    count->setRange(1, 10000);
    window->setRange(1, 86400);
    window->setValue(300);
    severity->addItems({"info", "low", "medium", "high", "critical"});
    severity->setCurrentText("high");
    form->addRow(QCoreApplication::translate("FleetWindow", "Название"), name);
    form->addRow(QCoreApplication::translate("FleetWindow", "Сообщение содержит"), pattern);
    form->addRow(QCoreApplication::translate("FleetWindow", "Количество событий"), count);
    form->addRow(QCoreApplication::translate("FleetWindow", "За интервал, секунд"), window);
    form->addRow(QCoreApplication::translate("FleetWindow", "Приоритет"), severity);
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel);
    form->addRow(buttons);
    connect(buttons, &QDialogButtonBox::accepted, &d, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &d, &QDialog::reject);
    if (d.exec() == QDialog::Accepted)
        request("rules.save", {{"name", name->text()},
                               {"pattern", pattern->text()},
                               {"threshold", count->value()},
                               {"window_seconds", window->value()},
                               {"severity", severity->currentText()},
                               {"enabled", true}});
}
void FleetWindow::exportTable() {
    auto file = QFileDialog::getSaveFileName(
        this, QCoreApplication::translate("FleetWindow", "Экспорт показанной страницы"), {}, "CSV (*.csv)");
    if (file.isEmpty())
        return;
    auto *table = tables_[tabs_->currentIndex()];
    QByteArray output = "\xEF\xBB\xBF";
    auto quote = [](QString s) {
        if (!s.isEmpty() && QString("=+-@\t\r").contains(s.front()))
            s.prepend('\'');
        s.replace('"', "\"\"");
        return '"' + s + '"';
    };
    for (int row = -1; row < table->rowCount(); ++row) {
        QStringList fields;
        for (int col = 0; col < table->columnCount(); ++col)
            fields << quote(row < 0 ? table->horizontalHeaderItem(col)->text()
                                    : table->item(row, col)->text());
        output += fields.join(',').toUtf8() + "\r\n";
    }
    try {
        writePrivate(file, output);
        status_->setText(QCoreApplication::translate("FleetWindow", "Экспортирована текущая страница."));
    } catch (const std::exception &e) {
        status_->setText(e.what());
    }
}
} // namespace siem
