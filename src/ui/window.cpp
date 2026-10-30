#include "window.h"
#include "chart.h"
#include "core/firewall.h"
#include "ngfw_page.h"
#include "theme.h"
#include "visuals.h"
#include <QApplication>
#include <QBoxLayout>
#include <QButtonGroup>
#include <QCloseEvent>
#include <QDesktopServices>
#include <QDialogButtonBox>
#include <QDir>
#include <QFileDialog>
#include <QFormLayout>
#include <QGridLayout>
#include <QHeaderView>
#include <QHostInfo>
#include <QInputDialog>
#include <QJsonArray>
#include <QJsonDocument>
#include <QMessageBox>
#include <QNetworkInterface>
#include <QPainter>
#include <QPainterPath>
#include <QPushButton>
#include <QRegularExpression>
#include <QSaveFile>
#include <QScrollArea>
#include <QShortcut>
#include <QStandardPaths>
#include <QStyle>
#include <QTabWidget>
#include <QTextDocument>
#include <QtConcurrent>
#ifdef Q_OS_WIN
#include <windows.h>

#include <shellapi.h>
#endif

namespace siem {
namespace {
const QStringList titles = {"Обзор безопасности",
                            "Оповещения",
                            "Инциденты",
                            "События безопасности",
                            "Активы",
                            "Правила и NGFW",
                            "Антивирус",
                            "Сетевой движок",
                            "Отчёты",
                            "Настройки"};
const QStringList subtitles = {
    "Безопасность инфраструктуры в реальном времени", "События, которые требуют вашего внимания",
    "Расследование и реагирование на угрозы",         "Единый журнал событий вашей инфраструктуры",
    "Устройства, обнаруженные в источниках событий",  "Корреляция событий и политики сетевой защиты",
    "Проверка файлов, сигнатуры и карантин",          "Мониторинг DPDK и интеграция с FD.io VPP",
    "Экспорт данных и журнал действий аналитика",     "Подключения и параметры рабочего пространства"};
QLabel *label(const QString &text, const char *name = nullptr) {
    auto *l = new QLabel(text);
    l->setTextFormat(Qt::PlainText);
    if (name)
        l->setObjectName(name);
    return l;
}
QIcon icon(int index, const QColor &color = QColor("#aebcdb")) {
    QPixmap pix(48, 48);
    pix.fill(Qt::transparent);
    QPainter p(&pix);
    p.setRenderHint(QPainter::Antialiasing);
    p.scale(2, 2);
    p.setPen(QPen(color, 1.65, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
    if (index == 0) {
        p.drawRoundedRect(QRectF(4, 4, 16, 16), 3, 3);
        p.drawRect(QRectF(8, 8, 3, 3));
        p.drawLine(14, 9, 17, 9);
        p.drawLine(8, 15, 17, 15);
    } else if (index == 1) {
        QPainterPath path;
        path.moveTo(5, 17);
        path.lineTo(7, 14);
        path.lineTo(7, 9);
        path.cubicTo(7, 2, 17, 2, 17, 9);
        path.lineTo(17, 14);
        path.lineTo(19, 17);
        path.closeSubpath();
        p.drawPath(path);
        p.drawArc(QRectF(10, 17, 4, 4), 180 * 16, 180 * 16);
    } else if (index == 2) {
        p.drawRoundedRect(QRectF(5, 5, 14, 15), 2, 2);
        p.drawLine(9, 3, 15, 3);
        p.drawLine(8, 12, 11, 15);
        p.drawLine(11, 15, 17, 9);
    } else if (index == 3) {
        p.drawRoundedRect(QRectF(5, 3, 14, 18), 2, 2);
        for (int y = 8; y <= 16; y += 4)
            p.drawLine(9, y, 15, y);
    } else if (index == 4) {
        p.drawRoundedRect(QRectF(3, 4, 18, 13), 2, 2);
        p.drawLine(12, 17, 12, 21);
        p.drawLine(8, 21, 16, 21);
        p.drawLine(6, 13, 9, 10);
        p.drawLine(9, 10, 13, 13);
        p.drawLine(13, 13, 18, 8);
    } else if (index == 5) {
        for (int y : {6, 12, 18})
            p.drawLine(3, y, 21, y);
        p.setBrush(Qt::NoBrush);
        p.drawEllipse(QPointF(8, 6), 2, 2);
        p.drawEllipse(QPointF(16, 12), 2, 2);
        p.drawEllipse(QPointF(10, 18), 2, 2);
    } else if (index == 6) {
        QPainterPath path;
        path.moveTo(12, 2);
        path.lineTo(20, 6);
        path.lineTo(19, 14);
        path.quadTo(18, 19, 12, 22);
        path.quadTo(6, 19, 5, 14);
        path.lineTo(4, 6);
        path.closeSubpath();
        p.drawPath(path);
        p.drawLine(8, 12, 11, 15);
        p.drawLine(11, 15, 16, 9);
    } else if (index == 7) {
        p.drawLine(12, 6, 5, 17);
        p.drawLine(12, 6, 19, 17);
        p.drawLine(5, 17, 19, 17);
        p.setBrush(Qt::NoBrush);
        for (auto point : {QPointF(12, 5), QPointF(5, 18), QPointF(19, 18)})
            p.drawEllipse(point, 3, 3);
    } else if (index == 8) {
        p.drawLine(5, 20, 5, 14);
        p.drawLine(12, 20, 12, 5);
        p.drawLine(19, 20, 19, 10);
    } else if (index == 10) {
        p.drawEllipse(QPointF(10, 10), 6, 6);
        p.drawLine(15, 15, 21, 21);
    } else {
        p.drawEllipse(QPointF(12, 12), 7, 7);
        p.drawEllipse(QPointF(12, 12), 2, 2);
        for (int i = 0; i < 8; ++i) {
            p.save();
            p.translate(12, 12);
            p.rotate(i * 45);
            p.drawLine(0, 7, 0, 10);
            p.restore();
        }
    }
    return QIcon(pix);
}
QPushButton *button(const QString &text, const char *style = nullptr) {
    auto *b = new QPushButton(text);
    b->setCursor(Qt::PointingHandCursor);
    if (style)
        b->setObjectName(style);
    return b;
}
QFrame *card(QVBoxLayout **layout) {
    auto *f = new QFrame;
    f->setObjectName("card");
    *layout = new QVBoxLayout(f);
    (*layout)->setContentsMargins(18, 16, 18, 16);
    (*layout)->setSpacing(12);
    return f;
}
QWidget *scrollArea(QWidget *content) {
    auto *s = new QScrollArea;
    s->setWidgetResizable(true);
    s->setWidget(content);
    s->setFrameShape(QFrame::NoFrame);
    return s;
}
QTableWidget *table(const QStringList &headers) {
    auto *t = new QTableWidget(0, headers.size());
    t->setHorizontalHeaderLabels(headers);
    t->verticalHeader()->hide();
    t->verticalHeader()->setDefaultSectionSize(46);
    t->horizontalHeader()->setStretchLastSection(true);
    t->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    t->horizontalHeader()->setDefaultSectionSize(140);
    t->setSelectionBehavior(QAbstractItemView::SelectRows);
    t->setSelectionMode(QAbstractItemView::SingleSelection);
    t->setEditTriggers(QAbstractItemView::NoEditTriggers);
    t->setShowGrid(false);
    t->setAlternatingRowColors(true);
    t->setWordWrap(false);
    t->setMinimumHeight(180);
    return t;
}
QString localTime(const QVariant &v) {
    return QDateTime::fromString(v.toString(), Qt::ISODateWithMs).toLocalTime().toString("dd.MM  HH:mm:ss");
}
void populate(QTableWidget *t, const QList<QVariantMap> &rows, const QStringList &keys) {
    const auto selected = t->currentRow() >= 0 ? t->item(t->currentRow(), 0)->data(Qt::UserRole) : QVariant();
    QSignalBlocker block(t);
    t->setUpdatesEnabled(false);
    t->setRowCount(int(rows.size()));
    int restore = -1;
    for (int row = 0; row < rows.size(); ++row) {
        const auto &r = rows[row];
        for (int col = 0; col < keys.size(); ++col) {
            auto k = keys[col];
            QString value = r[k].toString();
            if (k == "time" || k == "last_seen")
                value = localTime(r[k]);
            if (k == "severity")
                value = severityLabel(value);
            if (k == "status")
                value = statusLabel(value);
            if (k == "enabled")
                value = r[k].toInt() ? "Включено" : "Выключено";
            auto *item = new QTableWidgetItem(value);
            item->setData(Qt::UserRole, r.value("id", r.value("host")));
            item->setToolTip(value);
            if (k == "severity") {
                auto s = r[k].toString();
                item->setForeground(QColor(s == "critical" ? "#cf3f64"
                                           : s == "high"   ? "#e05a68"
                                           : s == "medium" ? "#d78b25"
                                                           : "#8490aa"));
            }
            if (k == "status")
                item->setForeground(
                    QColor(r[k] == "resolved" ? "#17a77e"
                           : r[k] == "open"
                               ? "#da8e25"
                               : (qApp->palette().color(QPalette::Window).lightness() < 100 ? "#b89af4"
                                                                                            : "#7658ed")));
            t->setItem(row, col, item);
        }
        if (r.value("id", r.value("host")) == selected)
            restore = row;
    }
    if (restore >= 0)
        t->selectRow(restore);
    t->setUpdatesEnabled(true);
}
QWidget *badge(const QString &text, const QString &tone = "green") {
    auto *l = label(text);
    l->setObjectName("badge");
    l->setProperty("tone", tone);
    l->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed);
    return l;
}
bool save(const QString &path, const QByteArray &content, QString *error) {
    QSaveFile f(path);
    if (!f.open(QIODevice::WriteOnly) || f.write(content) != content.size() || !f.commit()) {
        *error = f.errorString();
        return false;
    }
    return true;
}
QComboBox *combo(const QStringList &list) {
    auto *c = new QComboBox;
    c->addItems(list);
    return c;
}
} // namespace

Window::Window(Store &s, bool demo)
    : store_(s), demo_(demo), collector_(s, this), scanner_(this), engines_(s, this) {
    setWindowTitle("Sentinel — Security workspace");
    setMinimumSize(1120, 760);
    resize(1600, 1040);
    setWindowIcon(QIcon(":/sentinel.svg"));
    auto *root = new QWidget;
    root->setObjectName("root");
    setCentralWidget(root);
    auto *outer = new QVBoxLayout(root);
    outer->setContentsMargins(20, 20, 20, 20);
    auto *surface = new QFrame;
    surface->setObjectName("surface");
    auto *surfaceLayout = new QVBoxLayout(surface);
    surfaceLayout->setContentsMargins(14, 12, 22, 14);
    surfaceLayout->setSpacing(0);
    outer->addWidget(surface);

    auto *top = new QWidget;
    top->setObjectName("topbar");
    top->setFixedHeight(66);
    auto *tl = new QHBoxLayout(top);
    tl->setContentsMargins(12, 0, 8, 8);
    tl->setSpacing(12);
    auto *brand = new QHBoxLayout;
    auto *brandIcon = label("✳", "brandMark");
    brandIcon->setFixedWidth(32);
    brand->addWidget(brandIcon);
    brand->addWidget(label("Sentinel", "brand"));
    auto *edition = label("SIEM", "edition");
    brand->addWidget(edition);
    tl->addLayout(brand);
    tl->addStretch();

    auto *capsule = new QFrame;
    capsule->setObjectName("navCapsule");
    auto *tabs = new QHBoxLayout(capsule);
    tabs->setContentsMargins(5, 5, 5, 5);
    tabs->setSpacing(3);
    const QList<QPair<int, QString>> links = {{0, "Обзор"},  {3, "События"}, {2, "Инциденты"},
                                              {4, "Активы"}, {5, "Правила"}, {8, "Отчёты"}};
    for (const auto &entry : links) {
        auto *b = button(entry.second, "topNav");
        b->setCheckable(true);
        b->setFixedHeight(36);
        tabs->addWidget(b);
        topNav_[entry.first] = b;
        connect(b, &QPushButton::clicked, this, [this, entry] { navigate(entry.first); });
    }
    tl->addWidget(capsule);
    tl->addStretch();
    auto *theme = button("◐", "roundButton");
    theme->setFixedSize(38, 38);
    theme->setToolTip("Включить / выключить ночную тему");
    theme->setAccessibleName("Ночная тема");
    connect(theme, &QPushButton::clicked, this,
            [this] { applyTheme(themeName_ == "night" ? lastLightTheme_ : "night"); });
    tl->addWidget(theme);
    auto *alert = button("", "roundButton");
    alert->setProperty("iconIndex", 1);
    alert->setIcon(icon(1, QColor("#4c4a51")));
    alert->setFixedSize(38, 38);
    alert->setToolTip("Оповещения");
    tl->addWidget(alert);
    auto *settingsButton = button("", "roundButton");
    settingsButton->setProperty("iconIndex", 9);
    settingsButton->setIcon(icon(9, QColor("#4c4a51")));
    settingsButton->setFixedSize(38, 38);
    settingsButton->setToolTip("Настройки");
    connect(settingsButton, &QPushButton::clicked, this, [this] { navigate(9); });
    tl->addWidget(settingsButton);
    auto *avatar = label("SA", "avatar");
    avatar->setAlignment(Qt::AlignCenter);
    avatar->setFixedSize(38, 38);
    avatar->setToolTip("SOC-аналитик");
    tl->addWidget(avatar);
    surfaceLayout->addWidget(top);

    auto *workspaceRow = new QHBoxLayout;
    workspaceRow->setSpacing(14);
    auto *side = new QWidget;
    side->setObjectName("sidebar");
    side->setFixedWidth(55);
    auto *sl = new QVBoxLayout(side);
    sl->setContentsMargins(5, 25, 5, 4);
    sl->setSpacing(9);
    auto *expandNav = button("☰", "roundButton");
    expandNav->setFixedSize(40, 40);
    expandNav->setCheckable(true);
    expandNav->setToolTip("Показать названия разделов");
    expandNav->setAccessibleName("Развернуть навигацию");
    sl->addWidget(expandNav);
    auto *group = new QButtonGroup(this);
    group->setExclusive(true);
    QStringList names = {"Панель мониторинга", "Оповещения", "Инциденты",      "События", "Активы",
                         "Правила и NGFW",     "Антивирус",  "Сетевой движок", "Отчёты",  "Настройки"};
    for (int i = 0; i < names.size(); ++i) {
        if (i == 9)
            sl->addStretch();
        auto *b = button("", "nav");
        b->setIcon(icon(i, QColor("#7c7983")));
        b->setIconSize(QSize(19, 19));
        b->setFixedSize(40, 40);
        b->setCheckable(true);
        b->setToolTip(names[i]);
        b->setAccessibleName(names[i]);
        group->addButton(b, i);
        nav_ << b;
        sl->addWidget(b);
        connect(b, &QPushButton::clicked, this, [this, i] { navigate(i); });
    }
    connect(expandNav, &QPushButton::toggled, this, [this, side, names](bool expanded) {
        side->setFixedWidth(expanded ? 204 : 55);
        for (int i = 0; i < nav_.size(); ++i) {
            nav_[i]->setFixedWidth(expanded ? 194 : 40);
            nav_[i]->setText(expanded ? names[i] : QString());
            nav_[i]->setProperty("expanded", expanded);
            nav_[i]->style()->unpolish(nav_[i]);
            nav_[i]->style()->polish(nav_[i]);
        }
        if (!demo_)
            settings_.setValue("ui/expandedNav", expanded);
    });
    expandNav->setChecked(!demo_ && settings_.value("ui/expandedNav", false).toBool());
    workspaceRow->addWidget(side);

    auto *workspace = new QWidget;
    workspace->setObjectName("workspace");
    auto *bl = new QVBoxLayout(workspace);
    bl->setContentsMargins(0, 14, 0, 0);
    bl->setSpacing(16);
    auto *heading = new QHBoxLayout;
    auto *ht = new QVBoxLayout;
    ht->setSpacing(4);
    title_ = label(titles[0], "title");
    subtitle_ = label(subtitles[0], "subtitle");
    ht->addWidget(title_);
    ht->addWidget(subtitle_);
    heading->addLayout(ht);
    heading->addStretch();
    search_ = new QLineEdit;
    search_->setObjectName("globalSearch");
    search_->setPlaceholderText("Найти событие…   Ctrl + K");
    search_->setMinimumWidth(200);
    search_->setMaximumWidth(260);
    search_->addAction(icon(10, QColor("#83808a")), QLineEdit::LeadingPosition);
    heading->addWidget(search_);
    range_ = combo({"Последние 24 часа", "Последние 7 дней", "Последние 30 дней"});
    range_->setObjectName("periodSelector");
    heading->addWidget(range_);
    bl->addLayout(heading);
    notice_ = label("", "notice");
    notice_->setWordWrap(true);
    notice_->hide();
    bl->addWidget(notice_);
    stack_ = new QStackedWidget;
    stack_->addWidget(dashboard());
    stack_->addWidget(eventsPage(true));
    stack_->addWidget(incidentsPage());
    stack_->addWidget(eventsPage(false));
    stack_->addWidget(assetsPage());
    stack_->addWidget(rulesPage());
    stack_->addWidget(antivirusPage());
    stack_->addWidget(enginesPage());
    stack_->addWidget(reportsPage());
    stack_->addWidget(settingsPage());
    bl->addWidget(stack_, 1);
    auto *bottom = new QHBoxLayout;
    footer_ =
        label(demo ? "●  Демо · пример данных" : "●  PostgreSQL · рабочее пространство", "workspaceStatus");
    bottom->addWidget(footer_);
    bottom->addStretch();
    auto *switcher = new QFrame;
    switcher->setObjectName("themeSwitcher");
    auto *themeLayout = new QHBoxLayout(switcher);
    themeLayout->setContentsMargins(4, 4, 4, 4);
    themeLayout->setSpacing(2);
    flowTheme_ = button("●  Flow", "themeOption");
    emberTheme_ = button("●  Ember", "themeOption");
    nightTheme_ = button("◐  Ночь", "themeOption");
    nightTheme_->setCheckable(true);
    nightTheme_->setFixedHeight(28);
    flowTheme_->setCheckable(true);
    emberTheme_->setCheckable(true);
    flowTheme_->setFixedHeight(28);
    emberTheme_->setFixedHeight(28);
    switcher->setFixedHeight(36);
    themeLayout->addWidget(flowTheme_);
    themeLayout->addWidget(emberTheme_);
    themeLayout->addWidget(nightTheme_);
    connect(nightTheme_, &QPushButton::clicked, this, [this] { applyTheme("night"); });
    connect(flowTheme_, &QPushButton::clicked, this, [this] { applyTheme("flow"); });
    connect(emberTheme_, &QPushButton::clicked, this, [this] { applyTheme("ember"); });
    bottom->addWidget(switcher);
    bottom->addStretch();
    bottom->addWidget(label("Локальная консоль  /  0.2", "workspaceStatus"));
    bl->addLayout(bottom);
    workspaceRow->addWidget(workspace, 1);
    surfaceLayout->addLayout(workspaceRow, 1);
    searchDebounce_.setSingleShot(true);
    searchDebounce_.setInterval(250);
    connect(search_, &QLineEdit::textChanged, this, [this] { searchDebounce_.start(); });
    connect(&searchDebounce_, &QTimer::timeout, this, [this] {
        eventPage_[0] = eventPage_[1] = 0;
        dirty_ = true;
        refreshData();
    });
    connect(search_, &QLineEdit::returnPressed, this, [this] { navigate(3); });
    connect(alert, &QPushButton::clicked, this, [this] { navigate(1); });
    connect(range_, qOverload<int>(&QComboBox::currentIndexChanged), this, [this] {
        eventPage_[0] = eventPage_[1] = 0;
        dirty_ = true;
        refreshData();
    });
    auto *shortcut = new QShortcut(QKeySequence("Ctrl+K"), this);
    connect(shortcut, &QShortcut::activated, search_, qOverload<>(&QLineEdit::setFocus));
    connect(&store_, &Store::changed, this, [this] { dirty_ = true; });
    connect(&collector_, &Collector::error, this, [this](const QString &e) { notify(e, true); });
    connect(&engines_, &Engines::changed, this, &Window::refreshEngines);
    connect(&scanner_, &Scanner::finished, this, [this](const ScanResult &r) {
        scanFindings_ = r.findings;
        findings_->setRowCount(int(r.findings.size()));
        for (int i = 0; i < r.findings.size(); ++i) {
            auto f = r.findings[i];
            findings_->setItem(i, 0, new QTableWidgetItem(f.path));
            findings_->setItem(i, 1, new QTableWidgetItem(f.signature));
            findings_->setItem(i, 2, new QTableWidgetItem(f.sha256));
            Event e;
            e.source = "Антивирус";
            e.host = QHostInfo::localHostName();
            e.category = "malware";
            e.severity = "high";
            e.message = "malware · " + f.signature + " · " + f.path;
            store_.ingest(e);
        }
        auto text =
            QString("%1 · Проверено: %2 · Обнаружено: %3 · Пропущено: %4\n%5")
                .arg(r.cancelled ? "Отменено" : "Проверка завершена")
                .arg(r.scanned)
                .arg(r.findings.size())
                .arg(r.skipped)
                .arg(r.clamUsed ? "ClamAV + локальные сигнатуры"
                                : "EICAR + локальные SHA-256. ClamAV недоступен; это ограниченная проверка.");
        if (!r.errors.isEmpty())
            text += "\nОшибки: " + r.errors.join('\n');
        scanStatus_->setText(text);
        store_.audit("antivirus.scan", text);
        dirty_ = true;
    });
    watchDebounce_.setSingleShot(true);
    watchDebounce_.setInterval(2000);
    connect(&watcher_, &QFileSystemWatcher::directoryChanged, this, [this] { watchDebounce_.start(); });
    connect(&watchDebounce_, &QTimer::timeout, this, [this] {
        if (!watchScan_->isChecked())
            return;
        if (scanner_.busy()) {
            watchDebounce_.start();
            return;
        }
        scan();
    });
    refresh_.setInterval(700);
    connect(&refresh_, &QTimer::timeout, this, [this] {
        if (dirty_)
            refreshData();
    });
    refresh_.start();
    externalRefresh_.setInterval(5000);
    connect(&externalRefresh_, &QTimer::timeout, this, [this] {
        if (isVisible())
            dirty_ = true;
    });
    externalRefresh_.start();
    for (const auto &entry :
         QList<QPair<QString, int>>{{"Ctrl+1", 0}, {"Ctrl+2", 2}, {"Ctrl+3", 3}, {"Ctrl+4", 5}}) {
        auto *key = new QShortcut(QKeySequence(entry.first), this);
        connect(key, &QShortcut::activated, this, [this, entry] { navigate(entry.second); });
    }
    auto *reload = new QShortcut(QKeySequence("F5"), this);
    connect(reload, &QShortcut::activated, this, [this] {
        refreshData();
        refreshEngines();
    });
    search_->setClearButtonEnabled(true);
    search_->setToolTip("Поиск по событиям, инцидентам и активам · Ctrl+K. Enter — открыть события.");
    navigate(0);
    refreshEngines();
    applyTheme(qApp->property("themeOverride").isValid() ? qApp->property("themeOverride").toString()
                                                         : settings_.value("ui/theme", "ember").toString());
    if (!demo_ && settings_.value("collector/enabled", false).toBool())
        startCollector();
}

QWidget *Window::dashboard() {
    auto *page = new QWidget;
    page->setObjectName("dashboard");
    auto *layout = new QVBoxLayout(page);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(16);

    auto *summary = new QHBoxLayout;
    summary->setSpacing(28);
    auto *intro = new QVBoxLayout;
    intro->setSpacing(5);
    intro->addWidget(label("ВСЁ В ОДНОМ ПРОСТРАНСТВЕ", "eyebrow"));
    auto *quick = button("＋  Импортировать события", "quietAction");
    connect(quick, &QPushButton::clicked, this, &Window::importEvents);
    intro->addWidget(quick, 0, Qt::AlignLeft);
    summary->addLayout(intro, 2);
    const QStringList names = {"Всего событий", "Открытых инцидентов", "Файлов в карантине",
                               "Источников данных"};
    for (int i = 0; i < names.size(); ++i) {
        auto *metric = new QVBoxLayout;
        metric->setSpacing(3);
        metric->addWidget(label(names[i], "metricLabel"));
        auto *row = new QHBoxLayout;
        row->setSpacing(9);
        auto *value = label("0", "metricValue");
        metrics_ << value;
        row->addWidget(value);
        if (i == 1)
            row->addWidget(badge("в работе", "warm"), 0, Qt::AlignVCenter);
        else if (i == 2)
            row->addWidget(badge("изолировано", "green"), 0, Qt::AlignVCenter);
        row->addStretch();
        metric->addLayout(row);
        summary->addLayout(metric, 1);
    }
    layout->addLayout(summary);

    auto *hero = new QHBoxLayout;
    hero->setSpacing(14);
    QVBoxLayout *risk;
    auto *riskCard = card(&risk);
    riskCard->setMinimumWidth(250);
    auto *riskHead = new QHBoxLayout;
    riskHead->addWidget(label("Пульс безопасности", "cardTitle"));
    riskHead->addStretch();
    auto *riskOpen = button("↗", "cardArrow");
    riskOpen->setToolTip("События высокого приоритета");
    connect(riskOpen, &QPushButton::clicked, this, [this] { navigate(1); });
    riskHead->addWidget(riskOpen);
    risk->addLayout(riskHead);
    auto *riskBody = new QHBoxLayout;
    auto *riskNumbers = new QVBoxLayout;
    auto *riskCaption = label("Высокий\nприоритет", "muted");
    riskNumbers->addStretch();
    riskNumbers->addWidget(riskCaption);
    highEvents_ = label("0", "riskValue");
    riskNumbers->addWidget(highEvents_);
    riskNumbers->addWidget(label("событий за период", "tiny"));
    riskNumbers->addStretch();
    riskBody->addLayout(riskNumbers, 2);
    gauge_ = new GaugeWidget;
    gauge_->setMinimumWidth(140);
    gauge_->setMinimumHeight(116);
    riskBody->addWidget(gauge_, 3);
    risk->addLayout(riskBody, 1);
    auto *channels = new QHBoxLayout;
    channels->setSpacing(8);
    for (const auto &name : QStringList{"Syslog", "EVE", "DPDK", "Host"}) {
        auto *pill = label(name, "channelPill");
        pill->setAlignment(Qt::AlignCenter);
        channels->addWidget(pill);
    }
    risk->addLayout(channels);
    risk->addWidget(label("Каналы сбора событий", "tiny"));
    hero->addWidget(riskCard, 30);

    QVBoxLayout *focus;
    auto *focusCard = card(&focus);
    focusCard->setObjectName("focusCard");
    focusCard->setMinimumWidth(190);
    focus->setSpacing(8);
    auto *focusTitle = label("В центре\nвнимания", "focusTitle");
    focus->addWidget(focusTitle);
    auto *open = button("Открыть инциденты  ↗", "focusAction");
    open->setFixedHeight(32);
    connect(open, &QPushButton::clicked, this, [this] { navigate(2); });
    focus->addWidget(open, 0, Qt::AlignLeft);
    focus->addStretch();
    auto *focusNumberRow = new QHBoxLayout;
    focusIncidents_ = label("0", "focusNumber");
    focusNumberRow->addWidget(focusIncidents_);
    focusNumberRow->addStretch();
    focusNumberRow->addWidget(label("↗", "focusDecoration"));
    focus->addLayout(focusNumberRow);
    focus->addWidget(label("Инцидентов ожидают\nвашего решения", "focusCaption"));
    hero->addWidget(focusCard, 21);

    QVBoxLayout *protection;
    auto *protectionCard = card(&protection);
    protectionCard->setMinimumWidth(255);
    protection->setSpacing(8);
    auto *protectionHead = new QHBoxLayout;
    protectionHead->addWidget(label("Модули защиты", "cardTitle"));
    protectionHead->addStretch();
    auto *configure = button("↗", "cardArrow");
    configure->setToolTip("Открыть правила защиты");
    connect(configure, &QPushButton::clicked, this, [this] { navigate(5); });
    protectionHead->addWidget(configure);
    protection->addLayout(protectionHead);
    QStringList moduleNames = {"Антивирус", "HTTP-сигнатуры", "Корреляция", "Firewall"};
    QList<int> moduleIcons = {6, 3, 7, 5};
    QList<int> modulePages = {6, 7, 5, 5};
    for (int i = 0; i < 4; ++i) {
        auto *row = new QFrame;
        row->setObjectName("protectionRow");
        row->setProperty("tone", i);
        auto *rl = new QHBoxLayout(row);
        rl->setContentsMargins(9, 5, 9, 5);
        rl->setSpacing(7);
        auto *go = button("", "moduleIcon");
        go->setProperty("iconIndex", moduleIcons[i]);
        go->setIcon(icon(moduleIcons[i], QColor("#57515e")));
        go->setIconSize(QSize(17, 17));
        go->setFixedSize(25, 25);
        go->setToolTip(moduleNames[i]);
        connect(go, &QPushButton::clicked, this, [this, modulePages, i] { navigate(modulePages[i]); });
        rl->addWidget(go);
        rl->addWidget(label(moduleNames[i], "moduleName"));
        rl->addStretch();
        auto *state = label("По запросу", "moduleState");
        moduleStates_ << state;
        rl->addWidget(state);
        protection->addWidget(row);
    }
    hero->addWidget(protectionCard, 26);

    QVBoxLayout *inventory;
    auto *inventoryCard = card(&inventory);
    inventoryCard->setMinimumWidth(215);
    auto *inventoryHead = new QHBoxLayout;
    inventoryHead->addWidget(label("Карта\nинфраструктуры", "cardTitle"));
    inventoryHead->addStretch();
    auto *inventoryOpen = button("↗", "cardArrow");
    inventoryOpen->setToolTip("Инвентаризация активов");
    connect(inventoryOpen, &QPushButton::clicked, this, [this] { navigate(4); });
    inventoryHead->addWidget(inventoryOpen);
    inventory->addLayout(inventoryHead);
    networkMap_ = new NetworkMapWidget;
    inventory->addWidget(networkMap_, 1);
    auto *assetRow = new QHBoxLayout;
    assetCount_ = label("0", "assetNumber");
    assetRow->addWidget(assetCount_);
    assetRow->addWidget(label("узлов\nв журналах", "tiny"));
    assetRow->addStretch();
    auto *assetOpen = button("→", "darkCircle");
    assetOpen->setFixedSize(32, 32);
    connect(assetOpen, &QPushButton::clicked, this, [this] { navigate(4); });
    assetRow->addWidget(assetOpen);
    inventory->addLayout(assetRow);
    hero->addWidget(inventoryCard, 23);
    layout->addLayout(hero, 5);

    auto *activity = new QHBoxLayout;
    activity->setSpacing(14);
    QVBoxLayout *chartLayout;
    auto *chartCard = card(&chartLayout);
    auto *chartHead = new QHBoxLayout;
    chartHead->addWidget(label("Активность событий", "cardTitle"));
    chartHead->addStretch();
    chartHead->addWidget(label("●  Все события", "chartLegend"));
    auto *eventsOpen = button("↗", "cardArrow");
    connect(eventsOpen, &QPushButton::clicked, this, [this] { navigate(3); });
    chartHead->addWidget(eventsOpen);
    chartLayout->addLayout(chartHead);
    chartLayout->addWidget(label("Распределение событий за выбранный период", "tiny"));
    chart_ = new Chart;
    chartLayout->addWidget(chart_, 1);
    activity->addWidget(chartCard, 5);

    QVBoxLayout *recent;
    auto *recentCard = card(&recent);
    auto *recentHead = new QHBoxLayout;
    recentHead->addWidget(label("Очередь расследований", "cardTitle"));
    recentHead->addStretch();
    auto *all = button("Все инциденты  ↗", "link");
    connect(all, &QPushButton::clicked, this, [this] { navigate(2); });
    recentHead->addWidget(all);
    recent->addLayout(recentHead);
    recent->addWidget(label("Последние события, требующие внимания", "tiny"));
    latest_ = table({"Угроза", "Приоритет", "Статус"});
    latest_->setObjectName("recentTable");
    latest_->setColumnWidth(0, 290);
    latest_->setColumnWidth(1, 120);
    latest_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    latest_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    latest_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    latest_->verticalHeader()->setDefaultSectionSize(49);
    latest_->setMinimumHeight(235);
    latest_->setAlternatingRowColors(false);
    recent->addWidget(latest_, 1);
    connect(latest_, &QTableWidget::cellDoubleClicked, this, [this](int, int) { navigate(2); });
    activity->addWidget(recentCard, 6);
    layout->addLayout(activity, 6);

    QVBoxLayout *network;
    auto *networkCard = card(&network);
    networkCard->setObjectName("networkStrip");
    network->setContentsMargins(18, 12, 18, 12);
    auto *nl = new QHBoxLayout;
    nl->setSpacing(18);
    auto *networkTitle = new QVBoxLayout;
    networkTitle->setSpacing(3);
    networkTitle->addWidget(label("Сетевой движок", "stripTitle"));
    networkTitle->addWidget(label("DPDK + VPP", "tiny"));
    nl->addLayout(networkTitle);
    nl->addSpacing(6);
    dpdkBadge_ = label("DPDK · остановлен", "engineBadge");
    nl->addWidget(dpdkBadge_);
    auto metric = [&](const QString &caption, QLabel **value) {
        auto *column = new QVBoxLayout;
        column->setSpacing(2);
        column->addWidget(label(caption, "tiny"));
        *value = label("—", "stripValue");
        column->addWidget(*value);
        nl->addLayout(column, 1);
    };
    metric("Пакетов", &dpdkPackets_);
    metric("Объём", &dpdkBytes_);
    metric("Отброшено", &dpdkDrops_);
    vppBadge_ = label("VPP · нет связи", "engineBadge");
    nl->addWidget(vppBadge_);
    auto *networkOpen = button("Подключить  ↗", "quietAction");
    connect(networkOpen, &QPushButton::clicked, this, [this] { navigate(7); });
    nl->addWidget(networkOpen);
    network->addLayout(nl);
    layout->addWidget(networkCard);
    return scrollArea(page);
}
QWidget *Window::eventsPage(bool alerts) {
    QVBoxLayout *l;
    auto *page = card(&l);
    auto *toolbar = new QHBoxLayout;
    toolbar->addWidget(label(alerts ? "Высокий и критический приоритет" : "Журнал событий", "cardTitle"));
    toolbar->addStretch();
    if (!alerts) {
        severity_ = combo({"Все приоритеты", "critical", "high", "medium", "low", "info"});
        toolbar->addWidget(severity_);
        connect(severity_, qOverload<int>(&QComboBox::currentIndexChanged), this, [this] {
            eventPage_[0] = 0;
            dirty_ = true;
            refreshData();
        });
        auto *load = button("Импорт журналов");
        toolbar->addWidget(load);
        connect(load, &QPushButton::clicked, this, &Window::importEvents);
    }
    auto *exportBtn = button("Экспорт страницы CSV");
    toolbar->addWidget(exportBtn);
    connect(exportBtn, &QPushButton::clicked, this, &Window::exportEvents);
    l->addLayout(toolbar);
    auto *t = table({"ID", "Время", "Источник", "Узел", "Приоритет", "Сообщение"});
    t->setColumnWidth(0, 65);
    t->setColumnWidth(1, 155);
    t->setColumnWidth(2, 130);
    t->setColumnWidth(3, 150);
    t->setColumnWidth(4, 130);
    l->addWidget(t, 1);
    const int slot = alerts ? 1 : 0;
    auto *paging = new QHBoxLayout;
    pageLabels_[slot] = label("", "muted");
    previousPage_[slot] = button("← Новее");
    nextPage_[slot] = button("Старее →");
    paging->addWidget(pageLabels_[slot]);
    paging->addStretch();
    paging->addWidget(previousPage_[slot]);
    paging->addWidget(nextPage_[slot]);
    l->addLayout(paging);
    connect(previousPage_[slot], &QPushButton::clicked, this, [this, slot] {
        eventPage_[slot] = qMax(0, eventPage_[slot] - 1);
        refreshData();
    });
    connect(nextPage_[slot], &QPushButton::clicked, this, [this, slot] {
        ++eventPage_[slot];
        refreshData();
    });
    if (alerts)
        alerts_ = t;
    else
        events_ = t;
    connect(t, &QTableWidget::cellDoubleClicked, this, [this, t](int, int) { eventDialog(t); });
    return page;
}
QWidget *Window::incidentsPage() {
    QVBoxLayout *l;
    auto *page = card(&l);
    auto *bar = new QHBoxLayout;
    bar->addWidget(label("Очередь расследований", "cardTitle"));
    bar->addStretch();
    auto *open = button("Открыть инцидент", "primary");
    bar->addWidget(open);
    connect(open, &QPushButton::clicked, this, &Window::incidentDialog);
    l->addLayout(bar);
    incidents_ = table({"ID", "Время", "Угроза", "Узел", "Приоритет", "Статус"});
    incidents_->setColumnWidth(0, 60);
    incidents_->setColumnWidth(1, 150);
    incidents_->setColumnWidth(2, 340);
    l->addWidget(incidents_, 1);
    connect(incidents_, &QTableWidget::cellDoubleClicked, this, [this](int, int) { incidentDialog(); });
    return page;
}
QWidget *Window::assetsPage() {
    QVBoxLayout *l;
    auto *page = card(&l);
    auto *bar = new QHBoxLayout;
    bar->addWidget(label("Инвентаризация из событий", "cardTitle"));
    bar->addStretch();
    auto *local = button("Добавить этот компьютер", "primary");
    bar->addWidget(local);
    connect(local, &QPushButton::clicked, this, [this] {
        Event e;
        e.source = "Host";
        e.host = QHostInfo::localHostName();
        e.category = "inventory";
        e.message = "Локальный актив · " + QSysInfo::prettyProductName();
        for (auto ip : QNetworkInterface::allAddresses())
            if (ip.protocol() == QAbstractSocket::IPv4Protocol && !ip.isLoopback()) {
                e.ip = ip.toString();
                break;
            }
        store_.ingest(e);
        notify("Компьютер добавлен в инвентаризацию");
    });
    l->addLayout(bar);
    assets_ = table({"Узел", "IP-адрес", "Последняя активность", "Источник"});
    assets_->setColumnWidth(0, 270);
    assets_->setColumnWidth(1, 210);
    assets_->setColumnWidth(2, 210);
    l->addWidget(assets_, 1);
    l->addWidget(label("Список пополняется при получении событий. Наличие актива не означает, что на нём "
                       "установлен агент защиты.",
                       "muted"));
    return page;
}
QWidget *Window::rulesPage() {
    QVBoxLayout *l;
    auto *page = card(&l);
    auto *tabs = new QTabWidget;
    l->addWidget(tabs);
    auto *cor = new QWidget;
    auto *cl = new QVBoxLayout(cor);
    auto *cb = new QHBoxLayout;
    cb->addWidget(label("Совпадение текста + порог за временное окно", "muted"));
    cb->addStretch();
    auto *add = button("Добавить правило", "primary"), *edit = button("Изменить"),
         *del = button("Удалить", "danger");
    for (auto *b : {add, edit, del})
        cb->addWidget(b);
    connect(add, &QPushButton::clicked, this, [this] { editCorrelation(false); });
    connect(edit, &QPushButton::clicked, this, [this] { editCorrelation(true); });
    connect(del, &QPushButton::clicked, this, [this] { deleteRow(rules_, "rules"); });
    cl->addLayout(cb);
    rules_ = table({"ID", "Название", "Содержит", "Порог", "Окно, сек.", "Приоритет", "Состояние"});
    rules_->setColumnWidth(0, 55);
    rules_->setColumnWidth(1, 220);
    rules_->setColumnWidth(2, 180);
    cl->addWidget(rules_, 1);
    tabs->addTab(cor, "Корреляция SIEM");
    ngfw_ = new NgfwPage(store_, demo_);
    tabs->insertTab(0, ngfw_, "Firewall / NGFW");
    tabs->setCurrentIndex(0);
    connect(ngfw_, &NgfwPage::notification, this, &Window::notify);
    return page;
}
QWidget *Window::antivirusPage() {
    QVBoxLayout *l;
    auto *page = card(&l);
    auto *path = new QHBoxLayout;
    scanPath_ = new QLineEdit;
    scanPath_->setPlaceholderText("Выберите файл или папку для проверки");
    path->addWidget(scanPath_, 1);
    auto *file = button("Файл"), *dir = button("Папка"), *start = button("Проверить", "primary"),
         *cancel = button("Отмена");
    for (auto *b : {file, dir, start, cancel})
        path->addWidget(b);
    l->addLayout(path);
    connect(file, &QPushButton::clicked, this, [this] {
        auto p = QFileDialog::getOpenFileName(this, "Выбрать файл");
        if (!p.isEmpty())
            scanPath_->setText(p);
    });
    connect(dir, &QPushButton::clicked, this, [this] {
        auto p = QFileDialog::getExistingDirectory(this, "Выбрать папку");
        if (!p.isEmpty())
            scanPath_->setText(p);
    });
    connect(start, &QPushButton::clicked, this, &Window::scan);
    connect(cancel, &QPushButton::clicked, &scanner_, &Scanner::cancel);
    auto *options = new QHBoxLayout;
    watchScan_ = new QCheckBox("Проверять изменения в выбранной папке");
    options->addWidget(watchScan_);
    options->addStretch();
    auto *hashes = button("Импорт SHA-256");
    options->addWidget(hashes);
    connect(hashes, &QPushButton::clicked, this, &Window::loadHashes);
    connect(watchScan_, &QCheckBox::toggled, this, [this](bool enabled) {
        auto dirs = watcher_.directories();
        if (!dirs.isEmpty())
            watcher_.removePaths(dirs);
        if (enabled) {
            if (!QFileInfo(scanPath_->text()).isDir() || !watcher_.addPath(scanPath_->text())) {
                watchScan_->setChecked(false);
                notify("Выберите доступную папку", true);
                return;
            }
            scan();
        }
    });
    connect(scanPath_, &QLineEdit::textChanged, this, [this] { watchScan_->setChecked(false); });
    l->addLayout(options);
    scanStatus_ = label("Готов к проверке. EICAR и импортированные SHA-256 доступны сразу. ClamAV "
                        "подключается при наличии clamscan и его баз.",
                        "muted");
    scanStatus_->setWordWrap(true);
    l->addWidget(scanStatus_);
    auto *tabs = new QTabWidget;
    l->addWidget(tabs, 1);
    auto *detected = new QWidget;
    auto *dl = new QVBoxLayout(detected);
    findings_ = table({"Файл", "Сигнатура", "SHA-256"});
    findings_->setColumnWidth(0, 420);
    findings_->setColumnWidth(1, 220);
    dl->addWidget(findings_, 1);
    auto *isolateBtn = button("Поместить выбранный файл в карантин", "danger");
    dl->addWidget(isolateBtn, 0, Qt::AlignRight);
    connect(isolateBtn, &QPushButton::clicked, this, &Window::isolate);
    tabs->addTab(detected, "Обнаружения");
    auto *q = new QWidget;
    auto *ql = new QVBoxLayout(q);
    quarantine_ = table({"ID", "Исходный файл", "Сигнатура", "Дата", "Состояние"});
    quarantine_->setColumnWidth(0, 55);
    quarantine_->setColumnWidth(1, 400);
    quarantine_->setColumnWidth(2, 200);
    ql->addWidget(quarantine_, 1);
    auto *restoreBtn = button("Восстановить выбранный файл");
    ql->addWidget(restoreBtn, 0, Qt::AlignRight);
    connect(restoreBtn, &QPushButton::clicked, this, &Window::restore);
    tabs->addTab(q, "Карантин");
    l->addWidget(label("Наблюдение: только изменения непосредственного содержимого папки; не является "
                       "перехватом файлов в ядре.",
                       "muted"));
    return page;
}
QWidget *Window::enginesPage() {
    auto *page = new QWidget;
    auto *l = new QVBoxLayout(page);
    l->setContentsMargins(0, 0, 0, 0);
    QVBoxLayout *dl;
    auto *dp = card(&dl);
    auto *dh = new QHBoxLayout;
    dh->addWidget(label("DPDK · нативный пакетный сенсор", "cardTitle"));
    dh->addStretch();
    dpdkState_ = label("Не запущен", "muted");
    dh->addWidget(dpdkState_);
    dl->addLayout(dh);
    auto *desc = label("PCAP можно анализировать без доступа к сетевой карте. Для живого трафика задайте "
                       "EAL-параметры и подготовьте интерфейсы вручную.",
                       "muted");
    desc->setWordWrap(true);
    dl->addWidget(desc);
    ealArgs_ = new QLineEdit(settings_.value("dpdk/eal", "-l 0 --no-telemetry -a 0000:03:00.0").toString());
    dl->addWidget(ealArgs_);
    auto *db = new QHBoxLayout;
    inlineMode_ = new QCheckBox("Inline: 2 порта, блокировка L3/L4 + HTTP-сигнатур");
    db->addWidget(inlineMode_);
    db->addStretch();
    auto *pcap = button("Открыть PCAP"), *run = button("Запустить", "primary"), *stop = button("Остановить");
    for (auto *b : {pcap, run, stop})
        db->addWidget(b);
    connect(pcap, &QPushButton::clicked, this, [this] { startSensor(true); });
    connect(run, &QPushButton::clicked, this, [this] { startSensor(false); });
    connect(stop, &QPushButton::clicked, &engines_, &Engines::stopDpdk);
    dl->addLayout(db);
    l->addWidget(dp);
    QVBoxLayout *vl;
    auto *vp = card(&vl);
    auto *vh = new QHBoxLayout;
    vh->addWidget(label("FD.io VPP · интерфейсы и счётчики", "cardTitle"));
    vh->addStretch();
    vppState_ = label("Не подключён", "muted");
    vh->addWidget(vppState_);
    vl->addLayout(vh);
    auto *vb = new QHBoxLayout;
    vppSocket_ = new QLineEdit(settings_.value("vpp/socket", "/run/vpp/cli.sock").toString());
    vb->addWidget(vppSocket_, 1);
    auto *poll = button("Получить состояние", "primary");
    vb->addWidget(poll);
    connect(poll, &QPushButton::clicked, this, [this] {
        settings_.setValue("vpp/socket", vppSocket_->text());
        engines_.pollVpp(vppSocket_->text());
    });
    vl->addLayout(vb);
    vl->addWidget(label("VPP управляет собственными портами. Не назначайте один PCI-порт одновременно VPP и "
                        "отдельному DPDK-сенсору.",
                        "muted"));
    l->addWidget(vp);
    engineLog_ = new QTextEdit;
    engineLog_->setReadOnly(true);
    engineLog_->setPlaceholderText(
        "Здесь появятся реальные счётчики DPDK, вывод VPP и диагностика подключения.");
    engineLog_->setFontFamily("monospace");
    l->addWidget(engineLog_, 1);
    return page;
}
QWidget *Window::reportsPage() {
    QVBoxLayout *l;
    auto *page = card(&l);
    auto *bar = new QHBoxLayout;
    bar->addWidget(label("Отчёт центра безопасности", "cardTitle"));
    bar->addStretch();
    auto *json = button("Экспорт JSON"), *html = button("Сохранить отчёт HTML", "primary");
    bar->addWidget(json);
    bar->addWidget(html);
    connect(json, &QPushButton::clicked, this, [this] { saveReport(true); });
    connect(html, &QPushButton::clicked, this, [this] { saveReport(false); });
    l->addLayout(bar);
    reportPreview_ = new QTextEdit;
    reportPreview_->setReadOnly(true);
    reportPreview_->setMaximumHeight(190);
    l->addWidget(reportPreview_);
    l->addWidget(label("Журнал действий", "cardTitle"));
    audit_ = table({"Время", "Действие", "Подробности"});
    audit_->setColumnWidth(0, 175);
    audit_->setColumnWidth(1, 210);
    l->addWidget(audit_, 1);
    return page;
}
QWidget *Window::settingsPage() {
    QVBoxLayout *l;
    auto *page = card(&l);
    l->addWidget(label("Сбор событий", "cardTitle"));
    auto *form = new QFormLayout;
    syslogPort_ = new QSpinBox;
    syslogPort_->setRange(1024, 65535);
    syslogPort_->setValue(settings_.value("collector/port", 5514).toInt());
    form->addRow("Syslog UDP · 127.0.0.1", syslogPort_);
    autoCollect_ = new QCheckBox("Запускать коллектор при открытии приложения");
    autoCollect_->setChecked(settings_.value("collector/enabled", false).toBool());
    form->addRow("", autoCollect_);
    l->addLayout(form);
    auto *bar = new QHBoxLayout;
    auto *start = button("Запустить коллектор", "primary"), *stop = button("Остановить");
    bar->addWidget(start);
    bar->addWidget(stop);
    bar->addStretch();
    collectorState_ = label("Остановлен", "muted");
    bar->addWidget(collectorState_);
    l->addLayout(bar);
    connect(start, &QPushButton::clicked, this, &Window::startCollector);
    connect(stop, &QPushButton::clicked, this, [this] {
        collector_.stop();
        collectorState_->setText("Остановлен");
        store_.audit("collector.stop", "Остановлен пользователем");
    });
    connect(autoCollect_, &QCheckBox::toggled, this, [this](bool v) {
        if (!demo_)
            settings_.setValue("collector/enabled", v);
    });
    l->addSpacing(16);
    auto *hint = label(
        "Коллектор принимает RFC5424, обычный syslog и JSONL. Для удалённых источников используйте локальный "
        "rsyslog/syslog-ng с защищённой доставкой. Импорт Suricata EVE доступен в разделе «События».",
        "muted");
    hint->setWordWrap(true);
    l->addWidget(hint);
    l->addSpacing(20);
    l->addWidget(label("Хранилище", "cardTitle"));
    auto *db = label(store_.path());
    db->setTextInteractionFlags(Qt::TextSelectableByMouse);
    db->setWordWrap(true);
    l->addWidget(db);
    l->addWidget(
        label(demo_ ? "Демо использует временную SQLite; рабочие данные хранятся в PostgreSQL."
                    : "Параметры PostgreSQL выбираются при запуске. Пароль не сохраняется в настройках.",
              "muted"));
    auto *open = button("Открыть папку приложения");
    l->addWidget(open, 0, Qt::AlignLeft);
    connect(open, &QPushButton::clicked, this, [] {
        auto path = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
        QDir().mkpath(path);
        QDesktopServices::openUrl(QUrl::fromLocalFile(path));
    });
    l->addStretch();
    l->addWidget(label("SENTINEL SIEM  /  0.3.0\nC++20 · Qt 6 Widgets · PostgreSQL · DPDK · VPP", "muted"));
    return page;
}

void Window::navigate(int i) {
    if (i < 0 || i >= stack_->count())
        return;
    stack_->setCurrentIndex(i);
    title_->setText(titles[i]);
    subtitle_->setText(subtitles[i]);
    nav_[i]->setChecked(true);
    for (int n = 0; n < nav_.size(); ++n)
        nav_[n]->setIcon(icon(n, QColor(n == i ? "#ffffff" : themeName_ == "night" ? "#b8c3d9" : "#89808f")));
    for (auto it = topNav_.begin(); it != topNav_.end(); ++it)
        it.value()->setChecked(it.key() == i);
    dirty_ = true;
    refreshData();
}
void Window::applyTheme(const QString &name) {
    themeName_ = QStringList{"ember", "flow", "night"}.contains(name) ? name : "ember";
    if (themeName_ != "night")
        lastLightTheme_ = themeName_;
    qApp->setPalette(applicationPalette(themeName_));
    qApp->setStyleSheet(applicationStyle(themeName_));
    flowTheme_->setChecked(themeName_ == "flow");
    emberTheme_->setChecked(themeName_ == "ember");
    nightTheme_->setChecked(themeName_ == "night");
    chart_->setTheme(themeName_ == "flow");
    gauge_->setTheme(themeName_ == "flow");
    networkMap_->setTheme(themeName_ == "flow");
    chart_->setNightMode(themeName_ == "night");
    gauge_->setNightMode(themeName_ == "night");
    networkMap_->setNightMode(themeName_ == "night");
    for (auto *b : findChildren<QPushButton *>()) {
        if (b->property("iconIndex").isValid())
            b->setIcon(icon(b->property("iconIndex").toInt(),
                            QColor(themeName_ == "night" ? "#c2b3df" : "#57515e")));
    }
    for (int n = 0; n < nav_.size(); ++n)
        nav_[n]->setIcon(icon(n, QColor(nav_[n]->isChecked()    ? "#ffffff"
                                        : themeName_ == "night" ? "#b8c3d9"
                                                                : "#89808f")));
    if (!demo_)
        settings_.setValue("ui/theme", themeName_);
    dirty_ = true;
}
QString Window::since() const {
    return QDateTime::currentDateTimeUtc()
        .addDays(range_->currentIndex() == 0   ? -1
                 : range_->currentIndex() == 1 ? -7
                                               : -30)
        .toString(Qt::ISODateWithMs);
}
void Window::notify(const QString &message, bool error) {
    notice_->setText(message);
    notice_->setStyleSheet(error ? (themeName_ == "night"
                                        ? "background:#3c2533;color:#ffb1c0;border-color:#694152;"
                                        : "background:#fff0f2;color:#b4445c;border-color:#f4d3dc;")
                                 : "");
    notice_->show();
}
qint64 Window::selected(QTableWidget *t) const {
    return t->currentRow() < 0 ? 0 : t->item(t->currentRow(), 0)->data(Qt::UserRole).toLongLong();
}
void Window::refreshData() {
    dirty_ = false;
    try {
        const int page = stack_->currentIndex();
        const auto start = since();
        const QString term = "%" + search_->text() + "%";
        if (page == 1 || page == 3) {
            const int slot = page == 1 ? 1 : 0;
            QString sql = "SELECT id,time,source,host,severity,message FROM events WHERE time>=?";
            QVariantList args{start};
            if (!search_->text().isEmpty()) {
                sql += " AND (LOWER(message) LIKE LOWER(?) OR LOWER(host) LIKE LOWER(?) OR LOWER(source) "
                       "LIKE LOWER(?))";
                args << term << term << term;
            }
            if (page == 1)
                sql += " AND severity IN ('high','critical')";
            else if (severity_->currentIndex() > 0) {
                sql += " AND severity=?";
                args << severity_->currentText();
            }
            sql += " ORDER BY time DESC,id DESC LIMIT 251 OFFSET ?";
            args << eventPage_[slot] * 250;
            auto records = store_.rows(sql, args);
            const bool more = records.size() > 250;
            if (more)
                records.removeLast();
            populate(page == 1 ? alerts_ : events_, records,
                     {"id", "time", "source", "host", "severity", "message"});
            pageLabels_[slot]->setText(
                records.isEmpty() ? "Нет событий по выбранным условиям"
                                  : QString("Страница %1 · %2 записей · двойной щелчок — подробности")
                                        .arg(eventPage_[slot] + 1)
                                        .arg(records.size()));
            previousPage_[slot]->setEnabled(eventPage_[slot] > 0);
            nextPage_[slot]->setEnabled(more);
        } else if (page == 2) {
            populate(incidents_,
                     store_.rows("SELECT * FROM incidents WHERE time>=? AND (LOWER(title) LIKE LOWER(?) OR "
                                 "LOWER(host) LIKE LOWER(?)) ORDER BY id DESC LIMIT 1000",
                                 {start, term, term}),
                     {"id", "time", "title", "host", "severity", "status"});
        } else if (page == 4) {
            populate(assets_,
                     store_.rows("SELECT * FROM assets WHERE LOWER(host) LIKE LOWER(?) OR ip LIKE ? ORDER BY "
                                 "last_seen DESC LIMIT 1000",
                                 {term, term}),
                     {"host", "ip", "last_seen", "source"});
        } else if (page == 5) {
            populate(rules_, store_.rows("SELECT * FROM rules ORDER BY id"),
                     {"id", "name", "pattern", "threshold", "window_seconds", "severity", "enabled"});
        } else if (page == 6) {
            populate(quarantine_, store_.rows("SELECT * FROM quarantine ORDER BY id DESC LIMIT 1000"),
                     {"id", "original", "signature", "time", "state"});
        }
        if (page != 0 && page != 8)
            return;
        const auto summary =
            store_
                .rows("SELECT COUNT(*) AS total,COUNT(DISTINCT source) AS sources,SUM(CASE WHEN severity IN "
                      "('high','critical') THEN 1 ELSE 0 END) AS high FROM events WHERE time>=?",
                      {start})
                .value(0);
        const auto totalEvents = summary["total"].toLongLong(), highEvents = summary["high"].toLongLong();
        metrics_[0]->setText(QLocale().toString(totalEvents));
        metrics_[1]->setText(
            store_.scalar("SELECT COUNT(*) FROM incidents WHERE status IN ('open','investigating')")
                .toString());
        metrics_[2]->setText(
            store_.scalar("SELECT COUNT(*) FROM quarantine WHERE state='isolated'").toString());
        metrics_[3]->setText(summary["sources"].toString());
        if (page == 8) {
            populate(audit_, store_.rows("SELECT * FROM audit ORDER BY id DESC LIMIT 500"),
                     {"time", "action", "detail"});
            reportPreview_->setHtml(
                QString("<h2>Сводка за выбранный период</h2><p>%1 — %2</p><p><b>%3</b> событий &nbsp;&nbsp; "
                        "<b>%4</b> активных инцидентов &nbsp;&nbsp; <b>%5</b> файлов в карантине "
                        "&nbsp;&nbsp; <b>%6</b> источников</p><p>Хранилище: %7</p>")
                    .arg(QDateTime::fromString(start, Qt::ISODateWithMs)
                             .toLocalTime()
                             .toString("dd.MM.yyyy HH:mm"),
                         QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm"), metrics_[0]->text(),
                         metrics_[1]->text(), metrics_[2]->text(), metrics_[3]->text(),
                         store_.path().toHtmlEscaped()));
            return;
        }
        gauge_->setValues(totalEvents, highEvents);
        highEvents_->setText(QLocale().toString(highEvents));
        focusIncidents_->setText(metrics_[1]->text());
        const int nodes = store_.scalar("SELECT COUNT(*) FROM assets").toInt();
        networkMap_->setNodeCount(nodes);
        assetCount_->setText(QString::number(nodes));
        populate(latest_, store_.rows("SELECT * FROM incidents ORDER BY id DESC LIMIT 5"),
                 {"title", "severity", "status"});
        const int days = range_->currentIndex() == 0 ? 1 : range_->currentIndex() == 1 ? 7 : 30;
        const int count = days == 1 ? 24 : days, chars = days == 1 ? 13 : 10;
        const auto now = QDateTime::currentDateTimeUtc();
        QList<double> values(count, 0);
        QStringList labels;
        QMap<QString, qint64> grouped;
        const auto buckets = store_.rows(QString("SELECT substr(time,1,%1) AS bucket,COUNT(*) AS total FROM "
                                                 "events WHERE time>=? GROUP BY substr(time,1,%1)")
                                             .arg(chars),
                                         {start});
        for (const auto &r : buckets)
            grouped[r["bucket"].toString()] = r["total"].toLongLong();
        for (int i = 0; i < count; ++i) {
            const auto stamp =
                days == 1 ? now.addSecs(-(count - 1 - i) * 3600) : now.addDays(-(count - 1 - i));
            values[i] = double(grouped.value(stamp.toString(Qt::ISODateWithMs).left(chars)));
            labels << stamp.toLocalTime().toString(days == 1 ? "HH:00" : "dd.MM");
        }
        chart_->setValues(values, labels);
        moduleStates_[0]->setText(scanner_.busy() ? "Проверка…" : "По запросу");
        moduleStates_[1]->setText(engines_.dpdkRunning ? "Активен" : "Не запущен");
        moduleStates_[2]->setText(
            QString("%1 правил").arg(store_.scalar("SELECT COUNT(*) FROM rules WHERE enabled=1").toInt()));
        moduleStates_[3]->setText(ngfw_->wasAppliedHere() ? "Применялось" : "Настроить");
    } catch (const std::exception &e) {
        notify("Ошибка базы данных: " + QString::fromUtf8(e.what()), true);
    }
}
void Window::refreshEngines() {
    if (!dpdkState_)
        return;
    dpdkState_->setText(engines_.dpdkStatus);
    vppState_->setText(engines_.vppStatus);
    dpdkBadge_->setText(engines_.dpdkRunning ? "DPDK · работает" : "DPDK · остановлен");
    vppBadge_->setText(engines_.vppConnected ? "VPP · подключён" : "VPP · нет связи");
    auto stats = engines_.stats;
    if (!stats.isEmpty()) {
        dpdkPackets_->setText(QLocale().toString(qint64(stats["packets"].toDouble())));
        dpdkBytes_->setText(QString("%1 МБ").arg(stats["bytes"].toDouble() / 1048576, 0, 'f', 2));
        dpdkDrops_->setText(QString::number(qint64(stats["dropped"].toDouble())));
    }
    engineLog_->setPlainText("DPDK\n" + QString::fromUtf8(QJsonDocument(stats).toJson()) + "\n" +
                             engines_.diagnostics + "\nVPP\n" + engines_.vppOutput);
    dirty_ = true;
}
void Window::importEvents() {
    auto path = QFileDialog::getOpenFileName(this, "Импорт журнала", {},
                                             "Журналы (*.jsonl *.json *.log *.txt);;Все файлы (*)");
    if (path.isEmpty())
        return;
    QString error;
    QApplication::setOverrideCursor(Qt::WaitCursor);
    int count = 0;
    try {
        count = collector_.importFile(path, &error);
    } catch (const std::exception &e) {
        error = QString::fromUtf8(e.what());
    }
    QApplication::restoreOverrideCursor();
    notify(error.isEmpty() ? QString("Импортировано %1 событий").arg(count) : error, !error.isEmpty());
    dirty_ = true;
}
void Window::exportEvents() {
    auto *t = stack_->currentIndex() == 1 ? alerts_ : events_;
    auto path = QFileDialog::getSaveFileName(this, "Экспорт событий", "events.csv", "CSV (*.csv)");
    if (path.isEmpty())
        return;
    QString out;
    auto quote = [](QString s) {
        if (!s.isEmpty() && QString("=+-@\t\r").contains(s[0]))
            s.prepend('\'');
        s.replace('"', "\"\"");
        return '"' + s + '"';
    };
    for (int row = -1; row < t->rowCount(); ++row) {
        QStringList cells;
        for (int col = 0; col < t->columnCount(); ++col)
            cells << quote(row < 0 ? t->horizontalHeaderItem(col)->text() : t->item(row, col)->text());
        out += cells.join(',') + '\n';
    }
    QString error;
    if (save(path, QByteArray::fromHex("efbbbf") + out.toUtf8(), &error)) {
        store_.audit("events.export", path);
        notify("Видимые события экспортированы");
    } else
        notify(error, true);
}
void Window::eventDialog(QTableWidget *t) {
    auto id = selected(t);
    if (!id)
        return;
    auto r = store_.rows("SELECT * FROM events WHERE id=?", {id});
    if (r.isEmpty())
        return;
    QDialog d(this);
    d.setWindowTitle(QString("Событие #%1").arg(id));
    d.resize(760, 540);
    auto *l = new QVBoxLayout(&d);
    auto *text = new QTextEdit;
    text->setReadOnly(true);
    text->setPlainText(QString::fromUtf8(QJsonDocument(QJsonObject::fromVariantMap(r.first())).toJson()));
    l->addWidget(text);
    auto *close = new QDialogButtonBox(QDialogButtonBox::Close);
    l->addWidget(close);
    connect(close, &QDialogButtonBox::rejected, &d, &QDialog::reject);
    d.exec();
}
void Window::incidentDialog() {
    auto id = selected(incidents_);
    if (!id) {
        notify("Выберите инцидент");
        return;
    }
    auto r = store_.rows("SELECT * FROM incidents WHERE id=?", {id}).first();
    QDialog d(this);
    d.setWindowTitle(QString("Инцидент #%1").arg(id));
    d.resize(620, 420);
    auto *l = new QVBoxLayout(&d);
    auto *heading = label(r["title"].toString(), "cardTitle");
    heading->setWordWrap(true);
    l->addWidget(heading);
    l->addWidget(label(r["host"].toString() + " · " + severityLabel(r["severity"].toString()), "muted"));
    auto *status = combo({"Открыт", "Расследование", "Решён", "Ложное срабатывание"});
    QStringList codes = {"open", "investigating", "resolved", "false_positive"};
    status->setCurrentIndex(codes.indexOf(r["status"].toString()));
    l->addWidget(status);
    auto *note = new QTextEdit;
    note->setPlaceholderText("Заметка аналитика и предпринятые действия");
    note->setPlainText(r["note"].toString());
    l->addWidget(note);
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel);
    l->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::accepted, &d, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &d, &QDialog::reject);
    if (d.exec() == QDialog::Accepted) {
        store_.setIncidentStatus(id, codes[status->currentIndex()], note->toPlainText());
        refreshData();
    }
}
void Window::editCorrelation(bool editing) {
    auto id = editing ? selected(rules_) : 0;
    if (editing && !id) {
        notify("Выберите правило");
        return;
    }
    QVariantMap r;
    if (id)
        r = store_.rows("SELECT * FROM rules WHERE id=?", {id}).first();
    QDialog d(this);
    d.setWindowTitle(editing ? "Изменить правило" : "Новое правило корреляции");
    d.setMinimumWidth(520);
    auto *f = new QFormLayout(&d);
    auto *name = new QLineEdit(r["name"].toString()), *pattern = new QLineEdit(r["pattern"].toString());
    auto *threshold = new QSpinBox;
    threshold->setRange(1, 100000);
    threshold->setValue(r.value("threshold", 1).toInt());
    auto *window = new QSpinBox;
    window->setRange(1, 86400);
    window->setValue(r.value("window_seconds", 300).toInt());
    auto *severity = combo({"info", "low", "medium", "high", "critical"});
    severity->setCurrentText(r.value("severity", "high").toString());
    auto *enabled = new QCheckBox("Включено");
    enabled->setChecked(r.value("enabled", 1).toBool());
    f->addRow("Название", name);
    f->addRow("Текст содержит", pattern);
    f->addRow("Число событий", threshold);
    f->addRow("Окно, секунд", window);
    f->addRow("Приоритет", severity);
    f->addRow("", enabled);
    auto *err = label("");
    err->setWordWrap(true);
    f->addRow(err);
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel);
    f->addRow(buttons);
    connect(buttons, &QDialogButtonBox::rejected, &d, &QDialog::reject);
    connect(buttons, &QDialogButtonBox::accepted, &d, [&] {
        if (name->text().trimmed().isEmpty() || pattern->text().trimmed().isEmpty() ||
            name->text().size() > 100 || pattern->text().size() > 256) {
            err->setText("Укажите название (до 100) и непустой шаблон (до 256 символов)");
            return;
        }
        d.accept();
    });
    if (d.exec() != QDialog::Accepted)
        return;
    QVariantList values = {name->text(),    pattern->text(),         threshold->value(),
                           window->value(), severity->currentText(), int(enabled->isChecked())};
    if (id) {
        values << id;
        store_.exec(
            "UPDATE rules SET name=?,pattern=?,threshold=?,window_seconds=?,severity=?,enabled=? WHERE id=?",
            values);
        store_.exec("DELETE FROM matches WHERE rule_id=?", {id});
    } else
        store_.exec(
            "INSERT INTO rules(name,pattern,threshold,window_seconds,severity,enabled) VALUES(?,?,?,?,?,?)",
            values);
    store_.audit("rule.save", name->text());
    dirty_ = true;
}
void Window::deleteRow(QTableWidget *t, const QString &name) {
    auto id = selected(t);
    if (!id)
        return;
    if (QMessageBox::question(this, "Удаление", QString("Удалить правило #%1?").arg(id)) != QMessageBox::Yes)
        return;
    if (name == "rules")
        store_.exec("DELETE FROM matches WHERE rule_id=?", {id});
    store_.exec(QString("DELETE FROM %1 WHERE id=?").arg(name), {id});
    store_.audit(name + ".delete", QString::number(id));
    dirty_ = true;
}
void Window::scan() {
    if (scanner_.busy()) {
        notify("Проверка уже выполняется");
        return;
    }
    auto path = scanPath_->text().trimmed();
    if (path.isEmpty()) {
        notify("Выберите файл или папку");
        return;
    }
    if (scanner_.start(path, hashes_)) {
        scanStatus_->setText("Выполняется проверка… Можно продолжать работу или отменить её.");
        dirty_ = true;
    }
}
void Window::loadHashes() {
    auto path = QFileDialog::getOpenFileName(this, "Сигнатуры SHA-256", {}, "Текст (*.txt *.sha256)");
    if (path.isEmpty())
        return;
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly) || f.size() > 4 * 1024 * 1024) {
        notify("Не удалось прочитать файл (лимит 4 МБ)", true);
        return;
    }
    QMap<QString, QString> next;
    int invalid = 0;
    while (!f.atEnd()) {
        auto line = QString::fromUtf8(f.readLine()).trimmed();
        if (line.isEmpty() || line.startsWith('#'))
            continue;
        auto match = QRegularExpression("^([a-fA-F0-9]{64})(?:\\s+(.+))?$").match(line);
        if (!match.hasMatch()) {
            ++invalid;
            continue;
        }
        next.insert(match.captured(1).toLower(),
                    match.captured(2).isEmpty() ? "Custom-SHA256" : match.captured(2));
    }
    if (invalid) {
        notify(QString("Импорт отменён: некорректных строк — %1").arg(invalid), true);
        return;
    }
    hashes_ = next;
    store_.audit("antivirus.signatures", QString::number(hashes_.size()));
    notify(QString("Загружено SHA-256 сигнатур: %1 (на текущую сессию)").arg(hashes_.size()));
}
void Window::isolate() {
    int row = findings_->currentRow();
    if (row < 0 || row >= scanFindings_.size()) {
        notify("Выберите обнаруженный файл");
        return;
    }
    auto finding = scanFindings_[row];
    if (QMessageBox::question(this, "Карантин", "Переместить файл в карантин?\n" + finding.path) !=
        QMessageBox::Yes)
        return;
    QString error;
    auto root = demo_ ? QFileInfo(store_.path()).absolutePath()
                      : QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
    if (Scanner::quarantine(store_, finding, QDir(root).filePath("quarantine"), &error))
        notify("Файл изолирован. Восстановление доступно во вкладке карантина.");
    else
        notify(error, true);
    dirty_ = true;
}
void Window::restore() {
    auto id = selected(quarantine_);
    if (!id)
        return;
    auto row = store_.rows("SELECT * FROM quarantine WHERE id=?", {id}).first();
    if (QMessageBox::warning(this, "Восстановление",
                             "Восстановленный файл может содержать угрозу. Продолжить?",
                             QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel) != QMessageBox::Yes)
        return;
    auto path = QFileDialog::getSaveFileName(this, "Восстановить файл", row["original"].toString());
    if (path.isEmpty())
        return;
    QString error;
    if (Scanner::restore(store_, id, path, &error))
        notify("Файл восстановлен без разрешения на исполнение");
    else
        notify(error, true);
    dirty_ = true;
}
void Window::saveReport(bool json) {
    auto path = QFileDialog::getSaveFileName(this, "Сохранить отчёт",
                                             json ? "sentinel-report.json" : "sentinel-report.html",
                                             json ? "JSON (*.json)" : "HTML (*.html)");
    if (path.isEmpty())
        return;
    QString content;
    if (json)
        content = store_.exportJson();
    else {
        content =
            "<!doctype html><html lang='ru'><meta charset='utf-8'><title>Sentinel "
            "SIEM</title><style>body{font:15px "
            "system-ui;margin:48px;color:#17213f}table{border-collapse:collapse;width:100%}td,th{padding:"
            "10px;border-bottom:1px solid #ddd;text-align:left}</style><h1>Sentinel SIEM</h1>" +
            reportPreview_->toHtml() +
            "<h2>Инциденты</h2><table><tr><th>Время</th><th>Угроза</th><th>Узел</th><th>Статус</th></tr>";
        for (auto r :
             store_.rows("SELECT * FROM incidents WHERE time>=? ORDER BY id DESC LIMIT 1000", {since()}))
            content += "<tr><td>" + localTime(r["time"]) + "</td><td>" +
                       r["title"].toString().toHtmlEscaped() + "</td><td>" +
                       r["host"].toString().toHtmlEscaped() + "</td><td>" +
                       statusLabel(r["status"].toString()).toHtmlEscaped() + "</td></tr>";
        content += "</table></html>";
    }
    QString error;
    if (save(path, content.toUtf8(), &error)) {
        store_.audit("report.export", path);
        notify("Отчёт сохранён");
    } else
        notify(error, true);
}
void Window::startCollector() {
    QString error;
    if (collector_.start(quint16(syslogPort_->value()), &error)) {
        collectorState_->setText(QString("●  127.0.0.1:%1/udp").arg(collector_.port()));
        if (!demo_)
            settings_.setValue("collector/port", syslogPort_->value());
        notify("Коллектор принимает события");
    } else
        notify(error, true);
}
void Window::startSensor(bool pcap) {
    QStringList args;
    if (pcap) {
        auto path = QFileDialog::getOpenFileName(this, "Открыть захват", {}, "PCAP (*.pcap);;Все файлы (*)");
        if (path.isEmpty())
            return;
        args = {"--pcap", path, "--seconds", "5"};
    } else {
        if (QMessageBox::warning(
                this, "Запуск DPDK",
                inlineMode_->isChecked()
                    ? "Inline требует двух выделенных портов и перенаправляет трафик между ними. Сигнатуры "
                      "HTTP блокируются, правила берутся из сохранённого профиля DPDK. Запустить?"
                    : "Мониторинг потребляет пакеты выбранных портов. Используйте выделенный "
                      "SPAN/TAP-интерфейс. Запустить?",
                QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel) != QMessageBox::Yes)
            return;
        if (inlineMode_->isChecked())
            args << "--inline";
        args << "--";
        args += QProcess::splitCommand(ealArgs_->text());
        if (!demo_)
            settings_.setValue("dpdk/eal", ealArgs_->text());
    }
    const auto policy = ngfw_->savedDpdkPolicy();
    const auto error = validateDpdkPolicy(policy);
    if (!error.isEmpty()) {
        notify(error, true);
        return;
    }
    sensorPolicy_ = std::make_unique<QTemporaryFile>();
    if (!sensorPolicy_->open()) {
        notify(sensorPolicy_->errorString(), true);
        sensorPolicy_.reset();
        return;
    }
    const auto bytes = QJsonDocument(policy).toJson();
    if (sensorPolicy_->write(bytes) != bytes.size() || !sensorPolicy_->flush()) {
        notify("Не удалось записать профиль сенсора", true);
        sensorPolicy_.reset();
        return;
    }
    args.prepend(sensorPolicy_->fileName());
    args.prepend("--policy");
    engines_.startDpdk(args);
}
void Window::closeEvent(QCloseEvent *event) {
    if (ngfw_->isApplying()) {
        notify("Дождитесь завершения применения NGFW перед закрытием.", true);
        event->ignore();
        return;
    }
    if (ngfw_->hasUnsavedChanges()) {
        const auto answer =
            QMessageBox::question(this, "Несохранённый профиль NGFW", "Сохранить изменения перед закрытием?",
                                  QMessageBox::Save | QMessageBox::Discard | QMessageBox::Cancel);
        if (answer == QMessageBox::Cancel || (answer == QMessageBox::Save && !ngfw_->saveChanges())) {
            event->ignore();
            return;
        }
    }
    event->accept();
}
bool Window::smokeTest(const QString &screenshot, int finalPage) {
    for (int i = 0; i < stack_->count(); ++i) {
        navigate(i);
        refreshData();
        QApplication::processEvents();
        if (stack_->currentIndex() != i)
            return false;
    }
    navigate(finalPage);
    refreshData();
    QApplication::processEvents();
    if (!screenshot.isEmpty())
        return grab().save(screenshot);
    return true;
}
} // namespace siem
