#include "scanner.h"
#include <QCryptographicHash>
#include <QDirIterator>
#include <QElapsedTimer>
#include <QProcess>
#include <QRegularExpression>
#include <QSaveFile>
#include <QStandardPaths>
#include <QUuid>
#include <QtConcurrent>
namespace siem {
Scanner::Scanner(QObject *p) : QObject(p) {
    connect(&watcher_, &QFutureWatcher<ScanResult>::finished, this,
            [this] { emit finished(watcher_.result()); });
}
Scanner::~Scanner() {
    cancel();
    watcher_.waitForFinished();
}
bool Scanner::start(const QString &path, const QMap<QString, QString> &hashes, bool clam, const QStringList &exclusions) {
    if (busy())
        return false;
    cancel_ = false;
    watcher_.setFuture(
        QtConcurrent::run([this, path, hashes, clam, exclusions] { return scan(path, hashes, cancel_, clam, exclusions); }));
    return true;
}
void Scanner::cancel() {
    cancel_ = true;
}
QString Scanner::hashFile(const QString &path) {
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
        return {};
    QCryptographicHash h(QCryptographicHash::Sha256);
    if (!h.addData(&f))
        return {};
    return QString::fromLatin1(h.result().toHex());
}
ScanResult Scanner::scan(const QString &path, const QMap<QString, QString> &hashes, std::atomic_bool &cancel,
                         bool useClam, const QStringList &exclusions) {
    ScanResult r;
    QSet<QString> detected;
    const QByteArray eicar = QByteArray::fromBase64(
        "WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=");
    auto inspect = [&](const QString &p) {
        if (cancel)
            return;
        QFileInfo info(p);
        for (const auto &excluded : exclusions) {
            const auto prefix = QDir::cleanPath(QFileInfo(excluded).absoluteFilePath());
            if (info.absoluteFilePath() == prefix || info.absoluteFilePath().startsWith(prefix + '/')) {
                ++r.skipped;
                return;
            }
        }
        if (info.isSymLink() || !info.isFile() || info.size() > 256LL * 1024 * 1024) {
            ++r.skipped;
            return;
        }
        QFile f(p);
        if (!f.open(QIODevice::ReadOnly)) {
            ++r.skipped;
            if (r.errors.size() < 100)
                r.errors << p + ": " + f.errorString();
            return;
        }
        QCryptographicHash hash(QCryptographicHash::Sha256);
        QByteArray tail;
        bool test = false;
        qint64 total = 0;
        while (!f.atEnd() && !cancel) {
            auto b = f.read(1024 * 1024);
            if (b.isEmpty() && f.error() != QFileDevice::NoError)
                break;
            total += b.size();
            if (total > 256LL * 1024 * 1024)
                break;
            hash.addData(b);
            auto joined = tail + b;
            if (joined.contains(eicar))
                test = true;
            tail = joined.right(128);
        }
        if (cancel)
            return;
        if (f.error() != QFileDevice::NoError || total > 256LL * 1024 * 1024) {
            ++r.skipped;
            if (r.errors.size() < 100)
                r.errors << p + ": ошибка чтения / лимит размера";
            return;
        }
        ++r.scanned;
        auto sha = QString::fromLatin1(hash.result().toHex());
        auto sig = test ? QString("EICAR-Test-File") : hashes.value(sha);
        if (!sig.isEmpty()) {
            r.findings.append({info.absoluteFilePath(), sig, sha});
            detected.insert(info.absoluteFilePath());
        }
    };
    QFileInfo root(path);
    if (!root.exists()) {
        r.errors << "Путь не существует";
        return r;
    }
    if (root.isSymLink()) {
        r.errors << "Символические ссылки не сканируются";
        return r;
    }
    if (root.isDir()) {
        QDirIterator it(path, QDir::Files | QDir::Hidden | QDir::System | QDir::NoDotAndDotDot,
                        QDirIterator::Subdirectories);
        while (it.hasNext() && !cancel)
            inspect(it.next());
    } else
        inspect(root.absoluteFilePath());
    const auto clam = QStandardPaths::findExecutable("clamscan");
    if (useClam && !clam.isEmpty() && !cancel) {
        QProcess p;
        p.setProcessChannelMode(QProcess::MergedChannels);
        QStringList arguments{"--recursive", "--infected", "--stdout", "--max-filesize=256M", "--alert-exceeds-max=yes",
                              "--follow-dir-symlinks=0", "--follow-file-symlinks=0"};
        for (const auto &excluded : exclusions) {
            auto expression = "^" + QRegularExpression::escape(QDir::cleanPath(QFileInfo(excluded).absoluteFilePath())) + "(/|$)";
            arguments << "--exclude=" + expression << "--exclude-dir=" + expression;
        }
        arguments << "--" << root.absoluteFilePath();
        p.start(clam, arguments);
        if (!p.waitForStarted(5000))
            r.errors << "ClamAV: " + p.errorString();
        else {
            QElapsedTimer timer;
            timer.start();
            QByteArray buffer;
            bool overflow = false;
            while (p.state() != QProcess::NotRunning && !cancel && timer.elapsed() < 1800000) {
                p.waitForFinished(100);
                buffer += p.readAll();
                if (buffer.size() > 4 * 1024 * 1024) {
                    overflow = true;
                    break;
                }
            }
            if (p.state() != QProcess::NotRunning) {
                p.kill();
                p.waitForFinished(3000);
            }
            buffer += p.readAll();
            r.clamUsed = true;
            if (overflow)
                r.errors << "ClamAV: превышен лимит вывода";
            if (timer.elapsed() >= 1800000)
                r.errors << "ClamAV: превышено время проверки (30 минут)";
            if (!cancel && (p.exitStatus() != QProcess::NormalExit || p.exitCode() > 1))
                r.errors << "ClamAV: " + QString::fromUtf8(buffer).right(2000);
            for (auto line : QString::fromUtf8(buffer).split('\n')) {
                auto m = QRegularExpression("^(.*): (.+) FOUND\\s*$").match(line);
                if (m.hasMatch()) {
                    QString file = m.captured(1);
                    if (!detected.contains(file)) {
                        r.findings.append({file, m.captured(2), hashFile(file)});
                        detected.insert(file);
                    }
                }
            }
        }
    }
    r.cancelled = cancel;
    return r;
}
qint64 Scanner::quarantine(Store &store, const Finding &f, const QString &directory, QString *error) {
    const auto fail = [&](const QString &s) {
        *error = s;
        return qint64(0);
    };
    QFileInfo info(f.path);
    if (info.isSymLink() || !info.isFile() || f.sha256.isEmpty() || hashFile(f.path) != f.sha256)
        return fail("Файл изменился после проверки или недоступен. Проверьте его повторно.");
    if (!QDir().mkpath(directory))
        return fail("Не удалось создать карантин");
    QFile::setPermissions(directory, QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner);
    auto target =
        QDir(directory).filePath(QUuid::createUuid().toString(QUuid::WithoutBraces) + ".quarantine");
    QFile source(f.path);
    QSaveFile dest(target);
    if (!source.open(QIODevice::ReadOnly) || !dest.open(QIODevice::WriteOnly))
        return fail("Не удалось открыть файл");
    QCryptographicHash hash(QCryptographicHash::Sha256);
    while (!source.atEnd()) {
        auto b = source.read(1024 * 1024);
        if (b.isEmpty() && source.error() != QFileDevice::NoError)
            return fail("Ошибка чтения");
        hash.addData(b);
        if (dest.write(b) != b.size())
            return fail("Ошибка записи карантина");
    }
    if (QString::fromLatin1(hash.result().toHex()) != f.sha256)
        return fail("Файл изменился во время копирования");
    if (!dest.commit())
        return fail(dest.errorString());
    QFile::setPermissions(target, QFile::ReadOwner | QFile::WriteOwner);
    const auto id = store.exec(
        "INSERT INTO quarantine(original,stored,sha256,signature,time,state) VALUES(?,?,?,?,?,'copy')",
        {info.absoluteFilePath(), target, f.sha256, f.signature,
         QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs)});
    source.close();
    if (hashFile(f.path) != f.sha256 || !QFile::remove(f.path)) {
        store.audit("quarantine.copy", f.path);
        return fail("Копия сохранена, но исходный файл не удалён. Он ещё не изолирован.");
    }
    store.exec("UPDATE quarantine SET state='isolated' WHERE id=?", {id});
    store.audit("quarantine.isolate", f.path);
    return id;
}
bool Scanner::restore(Store &store, qint64 id, const QString &destination, QString *error) {
    auto list = store.rows("SELECT * FROM quarantine WHERE id=? AND state IN ('isolated','copy')", {id});
    if (list.isEmpty()) {
        *error = "Запись карантина не найдена";
        return false;
    }
    auto r = list.first();
    QFileInfo to(destination);
    if (to.exists() || to.isSymLink()) {
        *error = "Нельзя перезаписать существующий файл";
        return false;
    }
    if (hashFile(r["stored"].toString()) != r["sha256"].toString()) {
        *error = "Контрольная сумма карантина не совпадает";
        return false;
    }
    if (!QFile::copy(r["stored"].toString(), destination)) {
        *error = "Не удалось восстановить файл";
        return false;
    }
    QFile::setPermissions(destination, QFile::ReadOwner | QFile::WriteOwner);
    store.exec("UPDATE quarantine SET state='restored' WHERE id=?", {id});
    store.audit("quarantine.restore", destination);
    return true;
}
} // namespace siem
