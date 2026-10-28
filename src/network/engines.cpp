#include "engines.h"
#include "core/collector.h"
#include <QCoreApplication>
#include <QFileInfo>
#include <QJsonDocument>
#include <QStandardPaths>
namespace siem {
Engines::Engines(Store &s, QObject *p) : QObject(p), store_(s) {
    connect(&dpdk_, &QProcess::readyReadStandardError, this, [this] {
        diagnostics = (diagnostics + QString::fromLocal8Bit(dpdk_.readAllStandardError())).right(16000);
        emit changed();
    });
    connect(&dpdk_, &QProcess::readyReadStandardOutput, this, [this] {
        buffer_ += dpdk_.readAllStandardOutput();
        while (buffer_.contains('\n')) {
            auto line = buffer_.left(buffer_.indexOf('\n'));
            buffer_.remove(0, line.size() + 1);
            auto j = QJsonDocument::fromJson(line).object();
            auto type = j["type"].toString();
            if (type == "ready") {
                dpdkRunning = true;
                dpdkStatus = "Работает · " + j["mode"].toString();
            } else if (type == "stats")
                stats = j;
            else if (type == "event") {
                try {
                    store_.ingest(Collector::parse(line, "sensor", "DPDK"));
                } catch (const std::exception &e) {
                    diagnostics += QString::fromUtf8(e.what());
                }
            } else if (type == "error") {
                dpdkStatus = "Ошибка";
                diagnostics += j["message"].toString();
            }
            emit changed();
        }
        if (buffer_.size() > 1024 * 1024)
            buffer_.clear();
    });
    connect(&dpdk_, &QProcess::errorOccurred, this, [this](QProcess::ProcessError) {
        dpdkRunning = false;
        dpdkStatus = "Ошибка запуска";
        diagnostics += dpdk_.errorString();
        emit changed();
    });
    connect(&dpdk_, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
            [this](int code, QProcess::ExitStatus) {
                dpdkRunning = false;
                dpdkStatus = code == 0 ? "Остановлен" : "Завершён с ошибкой";
                store_.audit("dpdk.stop", QString::number(code));
                emit changed();
            });
    vppTimeout_.setSingleShot(true);
    connect(&vppTimeout_, &QTimer::timeout, this, [this] {
        vpp_.kill();
        vppStatus = "Тайм-аут подключения";
        vppConnected = false;
        emit changed();
    });
    connect(&vpp_, &QProcess::errorOccurred, this, [this](QProcess::ProcessError) {
        vppTimeout_.stop();
        vppConnected = false;
        vppStatus = "VPP недоступен";
        vppOutput = vpp_.errorString();
        emit changed();
    });
    connect(&vpp_, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
            [this](int code, QProcess::ExitStatus status) {
                vppTimeout_.stop();
                vppOutput = QString::fromLocal8Bit(vpp_.readAllStandardOutput()) +
                            QString::fromLocal8Bit(vpp_.readAllStandardError());
                vppConnected = code == 0 && status == QProcess::NormalExit &&
                               !vppOutput.contains("unknown input", Qt::CaseInsensitive);
                vppStatus = vppConnected ? "Подключён" : "Ошибка подключения";
                emit changed();
            });
}
Engines::~Engines() {
    dpdk_.terminate();
    if (!dpdk_.waitForFinished(1500)) {
        dpdk_.kill();
        dpdk_.waitForFinished(1000);
    }
    vpp_.kill();
    vpp_.waitForFinished(1000);
}
bool Engines::startDpdk(const QStringList &args) {
    if (dpdk_.state() != QProcess::NotRunning)
        return false;
    QString bin = QCoreApplication::applicationDirPath() + "/siem-dpdk";
    if (!QFileInfo::exists(bin))
        bin = QStandardPaths::findExecutable("siem-dpdk");
    if (bin.isEmpty()) {
        dpdkStatus = "DPDK sensor не установлен";
        emit changed();
        return false;
    }
    stats = {};
    buffer_.clear();
    diagnostics.clear();
    dpdkStatus = "Запуск…";
    dpdk_.start(bin, args);
    store_.audit("dpdk.start", args.join(' '));
    emit changed();
    return true;
}
void Engines::stopDpdk() {
    dpdk_.terminate();
    QTimer::singleShot(3000, &dpdk_, [this] {
        if (dpdk_.state() != QProcess::NotRunning)
            dpdk_.kill();
    });
}
void Engines::pollVpp(const QString &socket) {
    if (vpp_.state() != QProcess::NotRunning)
        return;
    auto bin = QStandardPaths::findExecutable("vppctl");
    if (bin.isEmpty()) {
        vppConnected = false;
        vppStatus = "vppctl не установлен";
        emit changed();
        return;
    }
    vppStatus = "Подключение…";
    vpp_.start(bin, {"-s", socket, "show", "interface"});
    vppTimeout_.start(5000);
    emit changed();
}
} // namespace siem
