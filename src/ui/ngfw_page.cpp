#include "ngfw_page.h"
#include "core/firewall.h"
#include <QApplication>
#include <QBoxLayout>
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QFileDialog>
#include <QFormLayout>
#include <QFutureWatcher>
#include <QHeaderView>
#include <QHostInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLineEdit>
#include <QMessageBox>
#include <QSaveFile>
#include <QScrollArea>
#include <QSpinBox>
#include <QStandardPaths>
#include <QSysInfo>
#include <QTabWidget>
#include <QtConcurrent>
#ifdef Q_OS_WIN
#include <windows.h>

#include <shellapi.h>
#endif

namespace siem {
namespace {
QPushButton *action(const QString &text, const char *style = nullptr) {
    auto *b = new QPushButton(text);
    if (style)
        b->setObjectName(style);
    b->setCursor(Qt::PointingHandCursor);
    return b;
}
QLabel *hint(const QString &text) {
    auto *l = new QLabel(text);
    l->setTextFormat(Qt::PlainText);
    l->setWordWrap(true);
    l->setObjectName("muted");
    return l;
}
QComboBox *choices(const QList<QPair<QString, QString>> &items, const QString &value = {}) {
    auto *c = new QComboBox;
    for (const auto &i : items)
        c->addItem(i.first, i.second);
    const int index = c->findData(value);
    if (index >= 0)
        c->setCurrentIndex(index);
    return c;
}
QComboBox *verdict(const QString &value) {
    return choices({{QCoreApplication::translate("NgfwPage", "Разрешить"), "accept"},
                    {QCoreApplication::translate("NgfwPage", "Блокировать"), "drop"}},
                   value);
}
QString display(const QString &key) {
    return QMap<QString, QString>{{"input", QCoreApplication::translate("NgfwPage", "Входящие")},
                                  {"output", QCoreApplication::translate("NgfwPage", "Исходящие")},
                                  {"forward", QCoreApplication::translate("NgfwPage", "Транзит")},
                                  {"accept", QCoreApplication::translate("NgfwPage", "Разрешить")},
                                  {"drop", QCoreApplication::translate("NgfwPage", "Блокировать")},
                                  {"reject", QCoreApplication::translate("NgfwPage", "Отклонить")},
                                  {"any", QCoreApplication::translate("NgfwPage", "Любой")},
                                  {"dnat", QCoreApplication::translate("NgfwPage", "Проброс порта / DNAT")},
                                  {"snat", QCoreApplication::translate("NgfwPage", "Подмена адреса / SNAT")},
                                  {"masquerade", "Masquerade"}}
        .value(key, key);
}
QTableWidget *grid(const QStringList &headers) {
    auto *t = new QTableWidget(0, headers.size());
    t->setHorizontalHeaderLabels(headers);
    t->verticalHeader()->hide();
    t->verticalHeader()->setDefaultSectionSize(40);
    t->horizontalHeader()->setStretchLastSection(true);
    t->setSelectionBehavior(QAbstractItemView::SelectRows);
    t->setSelectionMode(QAbstractItemView::SingleSelection);
    t->setEditTriggers(QAbstractItemView::NoEditTriggers);
    t->setAlternatingRowColors(true);
    t->setShowGrid(false);
    return t;
}
QJsonObject fresh(const QString &backend) {
    auto p = defaultFirewallPolicy();
    p["stateful"] = backend == "linux";
    auto i = p["inspection"].toObject();
    for (const auto &name : {"sql_injection", "xss", "path_traversal"})
        i[name] = backend == "dpdk";
    i["mode"] = backend == "dpdk" ? "block" : "alert";
    i["block_fragments"] = false;
    i["blocked_domains"] = QJsonArray();
    p["inspection"] = i;
    return p;
}
} // namespace

NgfwPage::NgfwPage(Store &store, bool demo, QWidget *parent) : QWidget(parent), store_(store), demo_(demo) {
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(4, 12, 4, 0);
    auto *bar = new QHBoxLayout;
    bar->addWidget(new QLabel(QCoreApplication::translate("NgfwPage", "Профиль защиты")));
    backendBox_ = choices({{QCoreApplication::translate("NgfwPage", "Linux · шлюз и компьютер"), "linux"},
                           {QCoreApplication::translate("NgfwPage", "DPDK · транзит и HTTP"), "dpdk"},
                           {QCoreApplication::translate("NgfwPage", "Windows · компьютер"), "windows"}});
    backendBox_->setObjectName("ngfwBackend");
    backendBox_->setAccessibleName(QCoreApplication::translate("NgfwPage", "Движок NGFW"));
    bar->addWidget(backendBox_);
    bar->addStretch();
    auto *import = action(QCoreApplication::translate("NgfwPage", "Импорт JSON")),
         *exportButton = action(QCoreApplication::translate("NgfwPage", "Экспорт JSON"));
    bar->addWidget(import);
    bar->addWidget(exportButton);
    layout->addLayout(bar);
    capabilities_ = hint("");
    layout->addWidget(capabilities_);
    auto *tabs = new QTabWidget;
    layout->addWidget(tabs, 1);
    auto *rulePage = new QWidget;
    auto *rl = new QVBoxLayout(rulePage);
    auto *rb = new QHBoxLayout;
    const QStringList ruleActions = {QCoreApplication::translate("NgfwPage", "＋ Добавить"),
                                     QCoreApplication::translate("NgfwPage", "Изменить"),
                                     QCoreApplication::translate("NgfwPage", "Копия"),
                                     QCoreApplication::translate("NgfwPage", "Вкл. / выкл."),
                                     "↑",
                                     "↓",
                                     QCoreApplication::translate("NgfwPage", "Удалить")};
    for (int n = 0; n < ruleActions.size(); ++n) {
        auto *b = action(ruleActions[n], n == 0 ? "primary" : nullptr);
        if (n == 0)
            b->setObjectName("ngfwAddRule");
        rb->addWidget(b);
        connect(b, &QPushButton::clicked, this, [this, n] {
            if (n < 2)
                editEntry(false, n == 1);
            else if (n == 2)
                duplicateRule();
            else if (n == 3)
                toggleRule();
            else if (n == 4 || n == 5)
                moveRule(n == 4 ? -1 : 1);
            else
                removeEntry(false);
        });
    }
    rb->addStretch();
    rl->addLayout(rb);
    rules_ = grid({"№", QCoreApplication::translate("NgfwPage", "Правило"),
                   QCoreApplication::translate("NgfwPage", "Направление"),
                   QCoreApplication::translate("NgfwPage", "Источник → назначение"),
                   QCoreApplication::translate("NgfwPage", "Протокол / порты"),
                   QCoreApplication::translate("NgfwPage", "Действие"),
                   QCoreApplication::translate("NgfwPage", "Включено")});
    rules_->setObjectName("ngfwRules");
    rules_->setColumnWidth(0, 42);
    rules_->setColumnWidth(1, 180);
    rules_->setColumnWidth(2, 110);
    rules_->setColumnWidth(3, 210);
    rules_->setColumnWidth(4, 180);
    rules_->setColumnWidth(5, 140);
    rules_->setColumnWidth(6, 100);
    rules_->horizontalHeader()->setStretchLastSection(false);
    rules_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    rl->addWidget(rules_, 1);
    rl->addWidget(hint(QCoreApplication::translate(
        "NgfwPage", "Linux и DPDK: первое совпадение определяет действие. Windows: блокирующие правила "
                    "имеют приоритет. Двойной щелчок открывает правило.")));
    tabs->addTab(rulePage, QCoreApplication::translate("NgfwPage", "1. Сетевые правила"));
    auto *base = new QWidget;
    auto *form = new QFormLayout(base);
    form->setSpacing(16);
    input_ = verdict("accept");
    output_ = verdict("accept");
    forward_ = verdict("accept");
    input_->setObjectName("ngfwDefaultInput");
    forward_->setObjectName("ngfwDefaultForward");
    form->addRow(QCoreApplication::translate("NgfwPage", "Входящие к компьютеру (input)"), input_);
    form->addRow(QCoreApplication::translate("NgfwPage", "Исходящие с компьютера (output)"), output_);
    form->addRow(QCoreApplication::translate("NgfwPage", "Трафик через шлюз (forward)"), forward_);
    stateful_ = new QCheckBox(
        QCoreApplication::translate("NgfwPage", "Разрешать established / related, отбрасывать invalid"));
    logDrops_ = new QCheckBox(
        QCoreApplication::translate("NgfwPage", "Писать блокировки политикой по умолчанию в журнал ядра"));
    form->addRow(QCoreApplication::translate("NgfwPage", "Состояния соединений"), stateful_);
    form->addRow(QCoreApplication::translate("NgfwPage", "Журналирование"), logDrops_);
    form->addRow(hint(QCoreApplication::translate(
        "NgfwPage",
        "Эти действия используются, если пакет не совпал ни с одним правилом. NAT и транзит требуют отдельно "
        "настроенной маршрутизации. Приложение не изменяет адреса интерфейсов и IP forwarding.")));
    tabs->addTab(base, QCoreApplication::translate("NgfwPage", "2. Политика по умолчанию"));
    auto *natPage = new QWidget;
    auto *nl = new QVBoxLayout(natPage);
    auto *nb = new QHBoxLayout;
    auto *na = action(QCoreApplication::translate("NgfwPage", "＋ Добавить NAT"), "primary"),
         *ne = action(QCoreApplication::translate("NgfwPage", "Изменить")),
         *nd = action(QCoreApplication::translate("NgfwPage", "Удалить"));
    for (auto *b : {na, ne, nd})
        nb->addWidget(b);
    nb->addStretch();
    nl->addLayout(nb);
    nat_ = grid({QCoreApplication::translate("NgfwPage", "Название"),
                 QCoreApplication::translate("NgfwPage", "Тип"),
                 QCoreApplication::translate("NgfwPage", "Интерфейс"),
                 QCoreApplication::translate("NgfwPage", "Адрес / порт"),
                 QCoreApplication::translate("NgfwPage", "Преобразование"),
                 QCoreApplication::translate("NgfwPage", "Включено")});
    nat_->setColumnWidth(0, 200);
    nat_->setColumnWidth(1, 190);
    nat_->setColumnWidth(3, 210);
    nl->addWidget(nat_, 1);
    nl->addWidget(hint(QCoreApplication::translate(
        "NgfwPage",
        "NAT поддерживается профилем Linux для IPv4. После преобразования пакет также должен быть "
        "разрешён сетевыми правилами. DNAT — входной интерфейс, SNAT / masquerade — выходной.")));
    tabs->addTab(natPage, "3. NAT");
    auto *inspection = new QWidget;
    auto *il = new QFormLayout(inspection);
    inspectionMode_ =
        choices({{QCoreApplication::translate("NgfwPage", "Блокировать обнаруженные угрозы"), "block"},
                 {QCoreApplication::translate("NgfwPage", "Только оповещать"), "alert"}});
    il->addRow(QCoreApplication::translate("NgfwPage", "Реакция DPDK inline"), inspectionMode_);
    sql_ = new QCheckBox("SQL injection");
    xss_ = new QCheckBox("XSS");
    traversal_ = new QCheckBox("Path traversal");
    fragments_ = new QCheckBox(QCoreApplication::translate("NgfwPage", "Блокировать IP-фрагменты"));
    for (auto *c : {sql_, xss_, traversal_, fragments_})
        il->addRow(c);
    domains_ = new QPlainTextEdit;
    domains_->setPlaceholderText("example.test\nblocked.example.test");
    domains_->setMaximumHeight(140);
    il->addRow(QCoreApplication::translate("NgfwPage", "Блокируемые HTTP Host\nпо одному домену в строке"),
               domains_);
    il->addRow(hint(QCoreApplication::translate(
        "NgfwPage", "Проверка открытого HTTP выполняется DPDK. Блокировка действует в inline с двумя "
                    "портами; мониторинг только создаёт события. TLS не расшифровывается. Это сигнатуры "
                    "отдельных пакетов, без сборки TCP-потока.")));
    tabs->addTab(inspection, QCoreApplication::translate("NgfwPage", "4. Проверка HTTP"));
    status_ = hint("");
    status_->setMinimumHeight(34);
    layout->addWidget(status_);
    auto *bottom = new QHBoxLayout;
    auto *previewButton = action(QCoreApplication::translate("NgfwPage", "Проверить и показать"));
    save_ = action(QCoreApplication::translate("NgfwPage", "Сохранить профиль"));
    save_->setObjectName("ngfwSave");
    rollback_ = action(QCoreApplication::translate("NgfwPage", "Откатить применение"));
    apply_ = action(QCoreApplication::translate("NgfwPage", "Применить к ОС"), "primary");
    bottom->addWidget(previewButton);
    bottom->addWidget(save_);
    bottom->addStretch();
    bottom->addWidget(rollback_);
    bottom->addWidget(apply_);
    layout->addLayout(bottom);
    connect(previewButton, &QPushButton::clicked, this, &NgfwPage::preview);
    connect(save_, &QPushButton::clicked, this, [this] { saveDraft(); });
    connect(apply_, &QPushButton::clicked, this, [this] { applyPolicy(false); });
    connect(rollback_, &QPushButton::clicked, this, [this] { applyPolicy(true); });
    connect(import, &QPushButton::clicked, this, &NgfwPage::importPolicy);
    connect(exportButton, &QPushButton::clicked, this, &NgfwPage::exportPolicy);
    connect(na, &QPushButton::clicked, this, [this] { editEntry(true, false); });
    connect(ne, &QPushButton::clicked, this, [this] { editEntry(true, true); });
    connect(nd, &QPushButton::clicked, this, [this] { removeEntry(true); });
    connect(rules_, &QTableWidget::cellDoubleClicked, this, [this] { editEntry(false, true); });
    connect(nat_, &QTableWidget::cellDoubleClicked, this, [this] { editEntry(true, true); });
    for (auto *c : {input_, output_, forward_, inspectionMode_})
        connect(c, &QComboBox::currentIndexChanged, this, [this] { changed(); });
    for (auto *c : {stateful_, logDrops_, sql_, xss_, traversal_, fragments_})
        connect(c, &QCheckBox::toggled, this, [this] { changed(); });
    connect(domains_, &QPlainTextEdit::textChanged, this, &NgfwPage::changed);
    connect(backendBox_, &QComboBox::currentIndexChanged, this, [this](int) {
        if (loading_)
            return;
        if (modified_) {
            auto answer = QMessageBox::question(
                this, QCoreApplication::translate("NgfwPage", "Несохранённый профиль"),
                QCoreApplication::translate("NgfwPage", "Сохранить изменения перед переключением?"),
                QMessageBox::Save | QMessageBox::Discard | QMessageBox::Cancel);
            if (answer == QMessageBox::Cancel || (answer == QMessageBox::Save && !saveDraft())) {
                QSignalBlocker block(backendBox_);
                backendBox_->setCurrentIndex(backendBox_->findData(backend_));
                return;
            }
        }
        loadProfile(backendBox_->currentData().toString());
    });
    connect(&process_, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
            [this](int code, QProcess::ExitStatus exit) {
                finished(code == 0 && exit == QProcess::NormalExit,
                         QString::fromLocal8Bit(process_.readAllStandardError()) +
                             QString::fromLocal8Bit(process_.readAllStandardOutput()));
            });
    connect(&process_, &QProcess::errorOccurred, this, [this](QProcess::ProcessError error) {
        if (error == QProcess::FailedToStart)
            finished(false, process_.errorString());
    });
#ifdef Q_OS_WIN
    loadProfile("windows");
#else
    loadProfile("linux");
#endif
}
QString NgfwPage::key(const QString &suffix, const QString &backend) const {
    const auto chosen = backend.isEmpty() ? backend_ : backend;
    if (suffix == "draft")
        return "ngfw." + chosen + '.' + suffix;
    auto machine = QSysInfo::machineUniqueId();
    if (machine.isEmpty())
        machine = QHostInfo::localHostName().toUtf8();
    const auto id =
        QString::fromLatin1(QCryptographicHash::hash(machine, QCryptographicHash::Sha256).toHex().left(24));
    return "ngfw." + chosen + ".host." + id + '.' + suffix;
}
bool NgfwPage::wasAppliedHere() const {
#ifdef Q_OS_WIN
    const QString backend = "windows";
#else
    const QString backend = "linux";
#endif
    return store_.scalar("SELECT value FROM meta WHERE key=?", {key("applied", backend)}).isValid();
}
QJsonObject NgfwPage::readProfile(const QString &backend) const {
    auto value =
        store_.scalar("SELECT value FROM meta WHERE key=?", {"ngfw." + backend + ".draft"}).toString();
    if (!value.isEmpty()) {
        QString error;
        auto p = normalizeFirewallPolicy(QJsonDocument::fromJson(value.toUtf8()).object(), &error);
        if (!error.isEmpty())
            throw std::runtime_error(error.toStdString());
        return p;
    }
    auto p = fresh(backend);
    if (backend == "linux") {
        QJsonArray rules;
        for (auto r : store_.rows("SELECT * FROM firewall ORDER BY id")) {
            r.remove("id");
            r["enabled"] = r["enabled"].toInt() != 0;
            rules.append(QJsonObject::fromVariantMap(r));
        }
        p["rules"] = rules;
        QString error;
        p = normalizeFirewallPolicy(p, &error);
        if (!error.isEmpty())
            throw std::runtime_error(error.toStdString());
    }
    return p;
}
QJsonObject NgfwPage::savedDpdkPolicy() const {
    return readProfile("dpdk");
}
void NgfwPage::loadProfile(const QString &backend) {
    backend_ = backend;
    policy_ = readProfile(backend);
    loadedJson_ = store_.scalar("SELECT value FROM meta WHERE key=?", {key("draft")}).toString();
    fill();
    modified_ = false;
    const auto stamp = store_.scalar("SELECT value FROM meta WHERE key=?", {key("applied_at")}).toString();
    showStatus(
        stamp.isEmpty()
            ? QCoreApplication::translate("NgfwPage", "Черновик. Сохранение профиля не включает защиту.")
            : QCoreApplication::translate("NgfwPage", "Последнее успешное применение из консоли: ") + stamp);
}
void NgfwPage::fill() {
    loading_ = true;
    backendBox_->setCurrentIndex(backendBox_->findData(backend_));
    const bool isLinux = backend_ == "linux", dpdk = backend_ == "dpdk";
    capabilities_->setText(
        isLinux ? QCoreApplication::translate(
                      "NgfwPage",
                      "Linux: IPv4/IPv6, состояния соединений, интерфейсы, порты, журнал, лимиты и NAT IPv4.")
        : dpdk
            ? QCoreApplication::translate(
                  "NgfwPage",
                  "DPDK: транзитные правила IPv4/IPv6, порты и сигнатуры HTTP. Сохранённый профиль "
                  "используется при следующем запуске сенсора.")
            : QCoreApplication::translate(
                  "NgfwPage",
                  "Windows: входящие и исходящие правила Windows Firewall. Системная политика по умолчанию "
                  "сохраняется; блокировка имеет приоритет."));
    const auto defaults = policy_["defaults"].toObject(), inspection = policy_["inspection"].toObject();
    for (auto entry :
         {qMakePair(input_, "input"), qMakePair(output_, "output"), qMakePair(forward_, "forward")})
        entry.first->setCurrentIndex(entry.first->findData(defaults[entry.second].toString()));
    input_->setEnabled(isLinux);
    output_->setEnabled(isLinux);
    forward_->setEnabled(isLinux || dpdk);
    stateful_->setChecked(policy_["stateful"].toBool());
    stateful_->setEnabled(isLinux);
    logDrops_->setChecked(policy_["log_drops"].toBool());
    logDrops_->setEnabled(isLinux);
    inspectionMode_->setCurrentIndex(inspectionMode_->findData(inspection["mode"].toString()));
    inspectionMode_->setEnabled(dpdk);
    sql_->setChecked(inspection["sql_injection"].toBool());
    xss_->setChecked(inspection["xss"].toBool());
    traversal_->setChecked(inspection["path_traversal"].toBool());
    fragments_->setChecked(inspection["block_fragments"].toBool());
    for (auto *c : {sql_, xss_, traversal_, fragments_})
        c->setEnabled(dpdk);
    QStringList names;
    for (const auto d : inspection["blocked_domains"].toArray())
        names << d.toString();
    domains_->setPlainText(names.join('\n'));
    domains_->setEnabled(dpdk);
    const auto rules = policy_["rules"].toArray();
    int selected = rules_->currentRow();
    rules_->setRowCount(rules.size());
    for (int r = 0; r < rules.size(); ++r) {
        auto o = rules[r].toObject();
        QStringList cells = {QString::number(r + 1),
                             o["name"].toString(),
                             display(o["direction"].toString()),
                             o["source"].toString() + " → " + o["destination"].toString(),
                             o["protocol"].toString().toUpper() + " / " + o["source_ports"].toString("any") +
                                 " → " + o["destination_ports"].toString("any"),
                             display(o["action"].toString()),
                             o["enabled"].toBool(true) ? QCoreApplication::translate("NgfwPage", "Да")
                                                       : QCoreApplication::translate("NgfwPage", "Нет")};
        for (int c = 0; c < cells.size(); ++c) {
            auto *i = new QTableWidgetItem(cells[c]);
            i->setToolTip(cells[c]);
            rules_->setItem(r, c, i);
        }
    }
    if (selected >= 0 && selected < rules.size())
        rules_->selectRow(selected);
    const auto nat = policy_["nat"].toArray();
    nat_->setRowCount(nat.size());
    for (int r = 0; r < nat.size(); ++r) {
        auto o = nat[r].toObject();
        QStringList cells = {o["name"].toString(),
                             display(o["type"].toString()),
                             o["interface"].toString(),
                             o["source"].toString() + " → " + o["destination"].toString() + ':' +
                                 QString::number(o["port"].toInt()),
                             o["to_address"].toString() + ':' + QString::number(o["to_port"].toInt()),
                             o["enabled"].toBool(true) ? QCoreApplication::translate("NgfwPage", "Да")
                                                       : QCoreApplication::translate("NgfwPage", "Нет")};
        for (int c = 0; c < cells.size(); ++c)
            nat_->setItem(r, c, new QTableWidgetItem(cells[c]));
    }
    apply_->setText(dpdk ? QCoreApplication::translate("NgfwPage", "Сохранить для сенсора")
                         : QCoreApplication::translate("NgfwPage", "Применить к ОС"));
    rollback_->setEnabled(!dpdk);
    loading_ = false;
}
void NgfwPage::changed() {
    if (loading_)
        return;
    modified_ = true;
    showStatus(QCoreApplication::translate(
        "NgfwPage", "Есть несохранённые изменения. Проверяйте профиль перед применением."));
}
QJsonObject NgfwPage::collect() const {
    auto p = policy_;
    p["defaults"] = QJsonObject{{"input", input_->currentData().toString()},
                                {"output", output_->currentData().toString()},
                                {"forward", forward_->currentData().toString()}};
    p["stateful"] = stateful_->isChecked();
    p["log_drops"] = logDrops_->isChecked();
    QJsonArray domains;
    for (const auto &name : domains_->toPlainText().split('\n', Qt::SkipEmptyParts))
        if (!name.trimmed().isEmpty())
            domains.append(name.trimmed().toLower());
    p["inspection"] = QJsonObject{{"mode", inspectionMode_->currentData().toString()},
                                  {"sql_injection", sql_->isChecked()},
                                  {"xss", xss_->isChecked()},
                                  {"path_traversal", traversal_->isChecked()},
                                  {"block_fragments", fragments_->isChecked()},
                                  {"blocked_domains", domains}};
    return p;
}
QString NgfwPage::validate(const QJsonObject &p) const {
    if (backend_ == "dpdk")
        return validateDpdkPolicy(p);
    if (backend_ == "windows")
        return validateWindowsPolicy(p);
    QString error;
    compileNftPolicy(p, &error);
    return error;
}
bool NgfwPage::saveDraft() {
    const auto p = collect();
    const auto error = validate(p);
    if (!error.isEmpty()) {
        showStatus(error, true);
        return false;
    }
    const auto json = QString::fromUtf8(QJsonDocument(p).toJson(QJsonDocument::Compact));
    if (!store_.compareAndSetMeta(key("draft"), loadedJson_, json)) {
        showStatus(
            QCoreApplication::translate(
                "NgfwPage",
                "Профиль изменён другой консолью. Экспортируйте свои изменения и откройте профиль заново."),
            true);
        return false;
    }
    loadedJson_ = json;
    policy_ = p;
    modified_ = false;
    store_.audit("ngfw.draft.saved", backend_);
    showStatus(
        backend_ == "dpdk"
            ? QCoreApplication::translate("NgfwPage", "Профиль сохранён. Перезапустите сенсор в разделе "
                                                      "«Сетевой движок», чтобы использовать его.")
            : QCoreApplication::translate(
                  "NgfwPage", "Профиль сохранён. Для включения правил нажмите «Применить к ОС»."));
    return true;
}
void NgfwPage::showStatus(const QString &text, bool error) {
    status_->setText(text);
    status_->setProperty("error", error);
    status_->setStyleSheet(error ? "color:#e36b7f" : "");
    if (error)
        emit notification(text, true);
}
void NgfwPage::editEntry(bool isNat, bool editing) {
    auto *table = isNat ? nat_ : rules_;
    auto array = policy_[isNat ? "nat" : "rules"].toArray();
    int index = editing ? table->currentRow() : -1;
    if (editing && index < 0) {
        showStatus(QCoreApplication::translate("NgfwPage", "Выберите строку в таблице."));
        return;
    }
    QJsonObject o = editing ? array[index].toObject() : QJsonObject();
    QDialog dialog(this);
    dialog.setWindowTitle(isNat ? QCoreApplication::translate("NgfwPage", "Правило NAT")
                                : QCoreApplication::translate("NgfwPage", "Сетевое правило"));
    dialog.resize(700, isNat ? 670 : 760);
    auto *outer = new QVBoxLayout(&dialog);
    auto *scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    auto *body = new QWidget;
    auto *form = new QFormLayout(body);
    form->setSpacing(12);
    scroll->setWidget(body);
    outer->addWidget(scroll, 1);
    auto line = [&](const QString &label, const QString &key, const QString &fallback = QString()) {
        auto *e = new QLineEdit(o[key].toString(fallback));
        form->addRow(label, e);
        return e;
    };
    auto *name = line(QCoreApplication::translate("NgfwPage", "Название"), "name");
    name->setObjectName("ngfwRuleName");
    auto *source = line(QCoreApplication::translate("NgfwPage", "Адрес источника / CIDR"), "source", "any");
    auto *destination =
        line(QCoreApplication::translate("NgfwPage", "Адрес назначения / CIDR"), "destination", "any");
    auto *protocol = choices({{QCoreApplication::translate("NgfwPage", "Любой"), "any"},
                              {"TCP", "tcp"},
                              {"UDP", "udp"},
                              {"ICMP", "icmp"}},
                             o["protocol"].toString("tcp"));
    form->addRow(QCoreApplication::translate("NgfwPage", "Протокол"), protocol);
    auto *enabled = new QCheckBox(QCoreApplication::translate("NgfwPage", "Правило включено"));
    enabled->setChecked(o["enabled"].toBool(true));
    QComboBox *direction = nullptr, *verdictBox = nullptr, *natType = nullptr;
    QLineEdit *sourcePorts = nullptr, *destinationPorts = nullptr, *in = nullptr, *out = nullptr,
              *comment = nullptr, *iface = nullptr, *target = nullptr;
    QCheckBox *logging = nullptr;
    QSpinBox *limit = nullptr, *port = nullptr, *targetPort = nullptr;
    if (!isNat) {
        direction = choices(
            backend_ == "dpdk" ? QList<QPair<QString, QString>>{{QCoreApplication::translate(
                                                                     "NgfwPage", "Через шлюз (forward)"),
                                                                 "forward"}}
            : backend_ == "windows"
                ? QList<QPair<QString, QString>>{{QCoreApplication::translate("NgfwPage",
                                                                              "К компьютеру (input)"),
                                                  "input"},
                                                 {QCoreApplication::translate("NgfwPage",
                                                                              "С компьютера (output)"),
                                                  "output"}}
                : QList<QPair<QString, QString>>{{QCoreApplication::translate("NgfwPage",
                                                                              "К компьютеру (input)"),
                                                  "input"},
                                                 {QCoreApplication::translate("NgfwPage",
                                                                              "С компьютера (output)"),
                                                  "output"},
                                                 {QCoreApplication::translate("NgfwPage",
                                                                              "Через шлюз (forward)"),
                                                  "forward"}},
            o["direction"].toString(backend_ == "dpdk" ? "forward" : "input"));
        form->addRow(QCoreApplication::translate("NgfwPage", "Направление"), direction);
        sourcePorts = line(QCoreApplication::translate("NgfwPage", "Порты источника"), "source_ports", "any");
        destinationPorts =
            line(QCoreApplication::translate("NgfwPage", "Порты назначения"), "destination_ports", "any");
        sourcePorts->setPlaceholderText(QCoreApplication::translate("NgfwPage", "any или 1024-65535"));
        destinationPorts->setPlaceholderText("80,443,8000-8080");
        form->addRow(hint(QCoreApplication::translate(
            "NgfwPage", "any — любой адрес или порт. Несколько портов разделяйте запятой; диапазон — "
                        "дефисом. Порты применяются только к TCP / UDP.")));
        verdictBox = choices({{QCoreApplication::translate("NgfwPage", "Разрешить"), "accept"},
                              {QCoreApplication::translate("NgfwPage", "Блокировать"), "drop"},
                              {QCoreApplication::translate("NgfwPage", "Отклонить с ответом"), "reject"}},
                             o["action"].toString("drop"));
        form->addRow(QCoreApplication::translate("NgfwPage", "Действие"), verdictBox);
        in = line(QCoreApplication::translate("NgfwPage", "Входной интерфейс"), "in_interface", "any");
        out = line(QCoreApplication::translate("NgfwPage", "Выходной интерфейс"), "out_interface", "any");
        in->setEnabled(backend_ == "linux");
        out->setEnabled(backend_ == "linux");
        logging = new QCheckBox(QCoreApplication::translate("NgfwPage", "Журналировать совпадения (Linux)"));
        logging->setChecked(o["log"].toBool());
        logging->setEnabled(backend_ == "linux");
        form->addRow(logging);
        limit = new QSpinBox;
        limit->setRange(0, 1000000);
        limit->setSpecialValueText(QCoreApplication::translate("NgfwPage", "Без лимита"));
        limit->setValue(o["rate_limit"].toInt());
        limit->setEnabled(backend_ == "linux");
        form->addRow(QCoreApplication::translate("NgfwPage", "Совпадений в секунду (Linux)"), limit);
        form->addRow(hint(QCoreApplication::translate(
            "NgfwPage",
            "Лимит доступен для разрешающих правил. Пакеты сверх лимита блокируются этим правилом.")));
        comment = line(QCoreApplication::translate("NgfwPage", "Комментарий"), "comment");
    } else {
        natType = choices({{QCoreApplication::translate("NgfwPage", "Проброс назначения (DNAT)"), "dnat"},
                           {QCoreApplication::translate("NgfwPage", "Подмена источника (SNAT)"), "snat"},
                           {QCoreApplication::translate("NgfwPage", "Адрес внешнего интерфейса (masquerade)"),
                            "masquerade"}},
                          o["type"].toString("masquerade"));
        form->addRow(QCoreApplication::translate("NgfwPage", "Тип преобразования"), natType);
        iface = line(QCoreApplication::translate("NgfwPage", "Интерфейс"), "interface", "any");
        port = new QSpinBox;
        port->setRange(0, 65535);
        port->setSpecialValueText(QCoreApplication::translate("NgfwPage", "Любой"));
        port->setValue(o["port"].toInt());
        form->addRow(QCoreApplication::translate("NgfwPage", "Исходный порт назначения"), port);
        target = line(QCoreApplication::translate("NgfwPage", "Новый IPv4-адрес"), "to_address");
        targetPort = new QSpinBox;
        targetPort->setRange(0, 65535);
        targetPort->setSpecialValueText(QCoreApplication::translate("NgfwPage", "Без изменения"));
        targetPort->setValue(o["to_port"].toInt());
        form->addRow(QCoreApplication::translate("NgfwPage", "Новый порт"), targetPort);
        form->addRow(hint(QCoreApplication::translate(
            "NgfwPage", "Для masquerade оставьте новый адрес пустым и новый порт равным 0. Для DNAT / SNAT "
                        "укажите один IPv4-адрес. NAT доступен только в Linux.")));
    }
    form->addRow(enabled);
    auto *errorLabel = hint("");
    outer->addWidget(errorLabel);
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel);
    buttons->button(QDialogButtonBox::Save)->setText(QCoreApplication::translate("NgfwPage", "Готово"));
    outer->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    connect(buttons, &QDialogButtonBox::accepted, &dialog, [&] {
        QJsonObject r{{"name", name->text().trimmed()},
                      {"source", source->text().trimmed()},
                      {"destination", destination->text().trimmed()},
                      {"protocol", protocol->currentData().toString()},
                      {"enabled", enabled->isChecked()}};
        if (!isNat) {
            r["direction"] = direction->currentData().toString();
            r["action"] = verdictBox->currentData().toString();
            r["source_ports"] = sourcePorts->text().trimmed();
            r["destination_ports"] = destinationPorts->text().trimmed();
            r["port"] = 0;
            r["in_interface"] = in->text().trimmed();
            r["out_interface"] = out->text().trimmed();
            r["log"] = logging->isChecked();
            r["rate_limit"] = limit->value();
            r["comment"] = comment->text();
        } else {
            r["type"] = natType->currentData().toString();
            r["interface"] = iface->text().trimmed();
            r["port"] = port->value();
            r["to_address"] = target->text().trimmed();
            r["to_port"] = targetPort->value();
        }
        auto candidate = array;
        if (index < 0)
            candidate.append(r);
        else
            candidate[index] = r;
        auto p = collect();
        p[isNat ? "nat" : "rules"] = candidate;
        const auto error = validate(p);
        if (!error.isEmpty()) {
            errorLabel->setText(error);
            return;
        }
        policy_ = p;
        dialog.accept();
        fill();
        changed();
        table->selectRow(index < 0 ? candidate.size() - 1 : index);
    });
    dialog.exec();
}
void NgfwPage::removeEntry(bool isNat) {
    auto *t = isNat ? nat_ : rules_;
    const int row = t->currentRow();
    if (row < 0) {
        showStatus(QCoreApplication::translate("NgfwPage", "Выберите строку в таблице."));
        return;
    }
    policy_ = collect();
    auto a = policy_[isNat ? "nat" : "rules"].toArray();
    a.removeAt(row);
    policy_[isNat ? "nat" : "rules"] = a;
    fill();
    changed();
}
void NgfwPage::moveRule(int delta) {
    const int row = rules_->currentRow();
    auto a = policy_["rules"].toArray();
    if (row < 0 || row + delta < 0 || row + delta >= a.size())
        return;
    auto item = a.takeAt(row);
    a.insert(row + delta, item);
    policy_ = collect();
    policy_["rules"] = a;
    fill();
    rules_->selectRow(row + delta);
    changed();
}
void NgfwPage::toggleRule() {
    const int row = rules_->currentRow();
    if (row < 0)
        return;
    auto a = policy_["rules"].toArray();
    auto r = a[row].toObject();
    r["enabled"] = !r["enabled"].toBool(true);
    a[row] = r;
    policy_ = collect();
    policy_["rules"] = a;
    fill();
    changed();
}
void NgfwPage::duplicateRule() {
    const int row = rules_->currentRow();
    if (row < 0)
        return;
    auto a = policy_["rules"].toArray();
    auto r = a[row].toObject();
    r["name"] = r["name"].toString() + QCoreApplication::translate("NgfwPage", " (копия)");
    a.insert(row + 1, r);
    policy_ = collect();
    policy_["rules"] = a;
    fill();
    rules_->selectRow(row + 1);
    changed();
}
void NgfwPage::importPolicy() {
    auto path = QFileDialog::getOpenFileName(
        this, QCoreApplication::translate("NgfwPage", "Импорт профиля NGFW"), {}, "JSON (*.json)");
    if (path.isEmpty())
        return;
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly) || file.size() > 2 * 1024 * 1024) {
        showStatus(
            QCoreApplication::translate("NgfwPage", "Не удалось прочитать файл или размер превышает 2 МБ."),
            true);
        return;
    }
    QJsonParseError parse;
    const auto document = QJsonDocument::fromJson(file.readAll(), &parse);
    QString error = parse.error == QJsonParseError::NoError ? QString() : parse.errorString();
    QJsonObject p;
    if (error.isEmpty())
        p = normalizeFirewallPolicy(
            document.isArray() ? QJsonValue(document.array()) : QJsonValue(document.object()), &error);
    if (error.isEmpty())
        error = validate(p);
    if (!error.isEmpty()) {
        showStatus(error, true);
        return;
    }
    if (modified_ &&
        QMessageBox::question(this, QCoreApplication::translate("NgfwPage", "Заменить черновик"),
                              QCoreApplication::translate(
                                  "NgfwPage", "Заменить несохранённые изменения импортируемым профилем?")) !=
            QMessageBox::Yes)
        return;
    policy_ = p;
    fill();
    changed();
    showStatus(QCoreApplication::translate("NgfwPage",
                                           "Профиль импортирован в редактор. Сохраните его после проверки."));
}
void NgfwPage::exportPolicy() {
    const auto p = collect();
    const auto error = validate(p);
    if (!error.isEmpty()) {
        showStatus(error, true);
        return;
    }
    auto path =
        QFileDialog::getSaveFileName(this, QCoreApplication::translate("NgfwPage", "Экспорт профиля NGFW"),
                                     "sentinel-" + backend_ + ".json", "JSON (*.json)");
    if (path.isEmpty())
        return;
    QSaveFile file(path);
    auto data = QJsonDocument(p).toJson();
    if (!file.open(QIODevice::WriteOnly) || file.write(data) != data.size() || !file.commit()) {
        showStatus(file.errorString(), true);
        return;
    }
    showStatus(QCoreApplication::translate("NgfwPage", "Профиль экспортирован: ") + path);
}
void NgfwPage::preview() {
    auto p = collect();
    const auto error = validate(p);
    if (!error.isEmpty()) {
        showStatus(error, true);
        return;
    }
    QString compileError;
    QDialog dialog(this);
    dialog.setWindowTitle(QCoreApplication::translate("NgfwPage", "Проверенный профиль · ") + backend_);
    dialog.resize(850, 640);
    auto *l = new QVBoxLayout(&dialog);
    l->addWidget(
        hint(QCoreApplication::translate("NgfwPage", "Проверка пройдена. Профиль ещё не применён.")));
    auto *text = new QPlainTextEdit;
    text->setReadOnly(true);
    text->setPlainText(backend_ == "linux" ? compileNftPolicy(p, &compileError)
                                           : QString::fromUtf8(QJsonDocument(p).toJson()));
    l->addWidget(text);
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Close);
    l->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    dialog.exec();
}
void NgfwPage::applyPolicy(bool rollback) {
    if (temporary_)
        return;
    if (backend_ == "dpdk") {
        saveDraft();
        return;
    }
    if (demo_) {
        showStatus(QCoreApplication::translate(
                       "NgfwPage",
                       "В деморежиме доступны редактор и экспорт. Для применения подключитесь к PostgreSQL."),
                   true);
        return;
    }
#ifdef Q_OS_WIN
    const QString native = "windows";
#else
    const QString native = "linux";
#endif
    if (backend_ != native) {
        showStatus(QCoreApplication::translate("NgfwPage", "Этот профиль нужно применять на ") + backend_ +
                       QCoreApplication::translate("NgfwPage", ". Здесь доступны настройка и экспорт."),
                   true);
        return;
    }
    QJsonObject p = collect();
    if (rollback) {
        auto previous = store_.scalar("SELECT value FROM meta WHERE key=?", {key("previous")}).toString();
        if (previous.isEmpty()) {
            showStatus(
                QCoreApplication::translate("NgfwPage", "Нет предыдущего успешного применения для отката."));
            return;
        }
        p = QJsonDocument::fromJson(previous.toUtf8()).object();
    }
    auto error = validate(p);
    if (!error.isEmpty()) {
        showStatus(error, true);
        return;
    }
    QMessageBox confirm(
        QMessageBox::Warning,
        rollback ? QCoreApplication::translate("NgfwPage", "Откатить NGFW")
                 : QCoreApplication::translate("NgfwPage", "Применить NGFW"),
        QCoreApplication::translate(
            "NgfwPage", "Будет изменена политика Sentinel на этом компьютере. Блокирующие правила могут "
                        "прервать соединения.\n"
                        "Linux заменяет таблицу Sentinel атомарно. Windows изменяет только правила Sentinel; "
                        "применение не атомарно."),
        QMessageBox::Apply | QMessageBox::Cancel, this);
    confirm.setDefaultButton(QMessageBox::Cancel);
    confirm.setDetailedText(QString::fromUtf8(QJsonDocument(p).toJson()));
    if (confirm.exec() != QMessageBox::Apply)
        return;
    if (!rollback && !saveDraft())
        return;
    temporary_ = std::make_unique<QTemporaryFile>(QDir::tempPath() + "/sentinel-ngfw-XXXXXX.json");
    if (!temporary_->open()) {
        showStatus(temporary_->errorString(), true);
        temporary_.reset();
        return;
    }
    const auto bytes = QJsonDocument(p).toJson();
    if (temporary_->write(bytes) != bytes.size() || !temporary_->flush()) {
        showStatus(QCoreApplication::translate("NgfwPage", "Не удалось записать профиль."), true);
        temporary_.reset();
        return;
    }
    pending_ = p;
    const auto helper = QCoreApplication::applicationDirPath() + "/siem-firewall-helper";
    setEnabled(false);
    showStatus(QCoreApplication::translate("NgfwPage", "Ожидание прав администратора и применения…"));
#ifdef Q_OS_WIN
    const auto filename = temporary_->fileName();
    auto *watch = new QFutureWatcher<int>(this);
    connect(watch, &QFutureWatcher<int>::finished, this, [this, watch] {
        finished(
            watch->result() == 0,
            QString(QCoreApplication::translate("NgfwPage", "Код Windows helper: %1")).arg(watch->result()));
        watch->deleteLater();
    });
    watch->setFuture(QtConcurrent::run([helper, filename] {
        const auto executable = helper + ".exe";
        const auto args = QString("--apply \"%1\"").arg(QDir::toNativeSeparators(filename));
        SHELLEXECUTEINFOW info{};
        info.cbSize = sizeof(info);
        info.fMask = SEE_MASK_NOCLOSEPROCESS;
        info.lpVerb = L"runas";
        info.lpFile = reinterpret_cast<LPCWSTR>(executable.utf16());
        info.lpParameters = reinterpret_cast<LPCWSTR>(args.utf16());
        info.nShow = SW_HIDE;
        if (!ShellExecuteExW(&info))
            return int(GetLastError());
        WaitForSingleObject(info.hProcess, INFINITE);
        DWORD code = 1;
        GetExitCodeProcess(info.hProcess, &code);
        CloseHandle(info.hProcess);
        return int(code);
    }));
#else
    auto pkexec = QStandardPaths::findExecutable("pkexec");
    if (pkexec.isEmpty()) {
        finished(false, QCoreApplication::translate(
                            "NgfwPage", "Установите polkit (pkexec) для запроса прав администратора."));
        return;
    }
    process_.start(pkexec, {helper, "--apply", temporary_->fileName()});
#endif
}
void NgfwPage::finished(bool success, const QString &message) {
    temporary_.reset();
    setEnabled(true);
    try {
        if (success) {
            auto prefix = key("applied");
            prefix.chop(QString(".applied").size());
            store_.recordPolicyApplication(prefix, pending_, backend_ + ": " + message.left(8192));
        } else
            store_.audit("ngfw.error", backend_ + ": " + message.left(8192));
    } catch (const std::exception &e) {
        showStatus((success ? QString(QCoreApplication::translate(
                                  "NgfwPage", "Правила применены к ОС, но история и откат не сохранены: "))
                            : QString(QCoreApplication::translate(
                                  "NgfwPage", "Применение не подтверждено, журнал недоступен: "))) +
                       QString::fromUtf8(e.what()),
                   true);
        return;
    }
    showStatus(success ? QCoreApplication::translate(
                             "NgfwPage", "Политика применена. История сохранена в журнале действий.")
                       : QCoreApplication::translate("NgfwPage", "Применение не подтверждено: ") + message,
               !success);
    emit notification(success ? QCoreApplication::translate("NgfwPage", "NGFW: политика применена")
                              : QCoreApplication::translate("NgfwPage", "NGFW: ошибка применения"),
                      !success);
}
} // namespace siem
