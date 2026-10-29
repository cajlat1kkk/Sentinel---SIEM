#pragma once
#include "core/collector.h"
#include "core/scanner.h"
#include "core/store.h"
#include "network/engines.h"
#include <QCheckBox>
#include <QComboBox>
#include <QFileSystemWatcher>
#include <QJsonArray>
#include <QLabel>
#include <QLineEdit>
#include <QMainWindow>
#include <QPushButton>
#include <QSettings>
#include <QSpinBox>
#include <QStackedWidget>
#include <QTableWidget>
#include <QTemporaryFile>
#include <QTextEdit>
#include <memory>
namespace siem {
class NgfwPage;
class Chart;
class GaugeWidget;
class NetworkMapWidget;
class Window : public QMainWindow {
    Q_OBJECT
  public:
    Window(Store &store, bool demo = false);
    void navigate(int index);
    bool smokeTest(const QString &screenshot, int finalPage = 0);

  protected:
    void closeEvent(QCloseEvent *event) override;

  private:
    Store &store_;
    bool demo_;
    Collector collector_;
    Scanner scanner_;
    Engines engines_;
    QSettings settings_;
    QStackedWidget *stack_;
    QLabel *title_, *subtitle_, *notice_, *collectorState_, *scanStatus_, *dpdkState_, *vppState_, *footer_;
    QLineEdit *search_, *scanPath_, *vppSocket_, *ealArgs_;
    QComboBox *range_, *severity_;
    QTableWidget *events_, *alerts_, *incidents_, *assets_, *latest_, *rules_, *findings_, *quarantine_,
        *audit_;
    QList<QLabel *> metrics_, moduleStates_;
    QLabel *dpdkPackets_, *dpdkBytes_, *dpdkDrops_, *dpdkBadge_, *vppBadge_;
    Chart *chart_;
    QTextEdit *engineLog_, *reportPreview_;
    QSpinBox *syslogPort_;
    QCheckBox *watchScan_, *inlineMode_, *autoCollect_;
    QList<QPushButton *> nav_;
    QMap<int, QPushButton *> topNav_;
    QPushButton *emberTheme_, *flowTheme_, *nightTheme_;
    QString themeName_ = "ember", lastLightTheme_ = "ember";
    NgfwPage *ngfw_;
    QTimer searchDebounce_, externalRefresh_;
    int eventPage_[2] = {0, 0};
    QLabel *pageLabels_[2];
    QPushButton *previousPage_[2], *nextPage_[2];
    GaugeWidget *gauge_;
    NetworkMapWidget *networkMap_;
    QLabel *focusIncidents_, *highEvents_, *assetCount_;
    QList<Finding> scanFindings_;
    QMap<QString, QString> hashes_;
    QFileSystemWatcher watcher_;
    QTimer refresh_, watchDebounce_;
    bool dirty_ = true;
    std::unique_ptr<QTemporaryFile> sensorPolicy_;
    QWidget *dashboard();
    QWidget *eventsPage(bool alerts);
    QWidget *incidentsPage();
    QWidget *assetsPage();
    QWidget *rulesPage();
    QWidget *antivirusPage();
    QWidget *enginesPage();
    QWidget *reportsPage();
    QWidget *settingsPage();
    void refreshData();
    void refreshEngines();
    void applyTheme(const QString &name);
    void importEvents();
    void exportEvents();
    void incidentDialog();
    void eventDialog(QTableWidget *table);
    void editCorrelation(bool editing);
    void deleteRow(QTableWidget *table, const QString &tableName);
    void scan();
    void loadHashes();
    void isolate();
    void restore();
    void saveReport(bool json);
    void startCollector();
    void startSensor(bool pcap);
    QString since() const;
    void notify(const QString &message, bool error = false);
    qint64 selected(QTableWidget *table) const;
};
} // namespace siem
