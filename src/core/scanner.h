#pragma once
#include "store.h"
#include <QFutureWatcher>
#include <QMap>
#include <atomic>
namespace siem {
struct Finding {
    QString path, signature, sha256;
};
struct ScanResult {
    int scanned = 0, skipped = 0;
    bool cancelled = false;
    bool clamUsed = false;
    QStringList errors;
    QList<Finding> findings;
};
class Scanner : public QObject {
    Q_OBJECT
  public:
    explicit Scanner(QObject *parent = nullptr);
    ~Scanner() override;
    bool start(const QString &path, const QMap<QString, QString> &hashes = {}, bool useClam = true,
               const QStringList &exclusions = {});
    void cancel();
    bool busy() const {
        return watcher_.isRunning();
    }
    static ScanResult scan(const QString &path, const QMap<QString, QString> &hashes,
                           std::atomic_bool &cancel, bool useClam, const QStringList &exclusions = {});
    static QString hashFile(const QString &path);
    static qint64 quarantine(Store &store, const Finding &finding, const QString &directory, QString *error);
    static bool restore(Store &store, qint64 id, const QString &destination, QString *error);
  signals:
    void finished(const siem::ScanResult &result);

  private:
    std::atomic_bool cancel_{false};
    QFutureWatcher<ScanResult> watcher_;
};
} // namespace siem
Q_DECLARE_METATYPE(siem::ScanResult)
