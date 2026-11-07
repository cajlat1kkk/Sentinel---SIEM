#include "engines.h"
#include "core/collector.h"
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QStandardPaths>

namespace siem {
namespace {
QString normalizeBdf(QString value) {
    value = value.trimmed().toLower();
    const int dot = value.lastIndexOf('.');
    if (dot > 0 && value.size() - dot > 2)
        value = value.left(dot + 2);
    return value;
}

QStringList allowedPciAddresses(const QStringList &args) {
    return Engines::pciAddresses(args.join(' '));
}
} // namespace

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
                const auto mode = j["mode"].toString();
                QString suffix;
                if (dpdkSource == "PCAP")
                    suffix = " · PCAP";
                else if (dpdkSource == "PCAP-probe")
                    suffix = " · PCAP · демо (без записи)";
                dpdkStatus = QString("Работает · %1%2").arg(mode.isEmpty() ? dpdkSource : mode, suffix);
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
                diagnostics += j["message"].toString() + '\n';
            }
            emit changed();
        }
        if (buffer_.size() > 1024 * 1024)
            buffer_.clear();
    });
    connect(&dpdk_, &QProcess::errorOccurred, this, [this](QProcess::ProcessError) {
        dpdkRunning = false;
        dpdkStatus = "Ошибка запуска";
        diagnostics += dpdk_.errorString() + '\n';
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
                               !vppOutput.contains("unknown input", Qt::CaseInsensitive) &&
                               !vppOutput.contains("failed", Qt::CaseInsensitive);
                if (vppConnected) {
                    const auto summary = parseVppInterfaces(vppOutput);
                    vppPorts_ = vppPciAddresses(vppOutput);
                    const int total = summary["total"].toInt();
                    const int up = summary["up"].toInt();
                    vppStatus = QString("Подключён · %1 интерфейс(ов), %2 link up").arg(total).arg(up);
                } else {
                    vppPorts_.clear();
                    vppStatus = vppOutput.isEmpty() ? "Ошибка подключения" : "VPP: " +
                        vppOutput.trimmed().left(160).replace('\n', ' ');
                }
                emit changed();
            });
    connect(&vppRefresh_, &QTimer::timeout, this, [this] {
        if (vpp_.state() == QProcess::NotRunning)
            pollVpp(vppSocket_);
    });
}

Engines::~Engines() {
    vppRefresh_.stop();
    dpdk_.terminate();
    if (!dpdk_.waitForFinished(1500)) {
        dpdk_.kill();
        dpdk_.waitForFinished(1000);
    }
    vpp_.kill();
    vpp_.waitForFinished(1000);
}

QList<Engines::PciPort> Engines::discoverPorts(const QString &sysfs) {
    QList<PciPort> ports;
    QDir dir(sysfs);
    const auto entries = dir.entryList(QDir::Dirs | QDir::NoDotAndDotDot, QDir::Name);
    for (const auto &entry : entries) {
        QFile classFile(dir.filePath(entry + "/class"));
        if (!classFile.open(QIODevice::ReadOnly))
            continue;
        const auto deviceClass = classFile.readAll().trimmed();
        if (!deviceClass.startsWith("0x0200"))
            continue;
        PciPort port;
        port.bdf = entry.toLower();
        const QFileInfo driver(dir.filePath(entry + "/driver"));
        if (driver.isSymLink())
            port.driver = QFileInfo(driver.symLinkTarget()).fileName();
        port.iommu = QFileInfo::exists(dir.filePath(entry + "/iommu_group"));
        ports << port;
    }
    return ports;
}

QJsonObject Engines::parseVppInterfaces(const QString &output) {
    int total = 0, up = 0;
    QStringList names;
    const auto lines = output.split('\n');
    for (const auto &raw : lines) {
        const auto line = raw.trimmed();
        const auto fields = line.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
        if (fields.size() < 3)
            continue;
        bool indexOk = false;
        fields[1].toInt(&indexOk);
        if (!indexOk)
            continue;
        const auto state = fields[2].toLower();
        if (state != "up" && state != "down" && state != "disabled" && state != "deleted")
            continue;
        ++total;
        if (state == "up")
            ++up;
        names << fields[0];
    }
    return {{"total", total}, {"up", up}, {"names", QJsonArray::fromStringList(names)}};
}

QStringList Engines::pciAddresses(const QString &text) {
    static const QRegularExpression option(
        R"((?:^|\s)(?:-a|--allow|-w|--pci-whitelist)[=\s]*([0-9a-fA-F:.]{7,}))");
    QStringList out;
    auto match = option.globalMatch(text);
    while (match.hasNext()) {
        auto value = normalizeBdf(match.next().captured(1));
        if (!value.isEmpty() && !out.contains(value))
            out << value;
    }
    return out;
}

QStringList Engines::vppPciAddresses(const QString &output) {
    static const QRegularExpression address(
        R"(\baddress\s+([0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-9a-fA-F]{1,2})\b)");
    QStringList out;
    auto match = address.globalMatch(output);
    while (match.hasNext()) {
        auto bdf = normalizeBdf(match.next().captured(1));
        if (!bdf.isEmpty() && !out.contains(bdf))
            out << bdf;
    }
    return out;
}

QString Engines::suggestedEalArgs() const {
    const auto busy = vppPciAddresses(vppOutput);
    const auto ports = discoverPorts();
    for (const auto &port : ports) {
        if (port.driver != "vfio-pci" || !port.iommu || busy.contains(port.bdf))
            continue;
        return QStringLiteral("-l 1 --no-telemetry -a %1").arg(port.bdf);
    }
    return {};
}

bool Engines::portUsedByVpp(const QStringList &args, QString *bdf) const {
    const auto busy = vppPciAddresses(vppOutput);
    for (const auto &used : allowedPciAddresses(args)) {
        if (busy.contains(used)) {
            if (bdf)
                *bdf = used;
            return true;
        }
    }
    return false;
}

void Engines::startVppMonitoring(const QString &socket, int intervalMs) {
    vppSocket_ = socket.trimmed().isEmpty() ? QStringLiteral("/run/vpp/cli.sock") : socket.trimmed();
    vppRefresh_.setInterval(qBound(5000, intervalMs, 300000));
    if (!vppRefresh_.isActive())
        vppRefresh_.start();
    pollVpp(vppSocket_);
}

void Engines::setStatus(const QString &text) {
    dpdkStatus = text;
    emit changed();
}

void Engines::stopVppMonitoring() {
    vppRefresh_.stop();
    vppTimeout_.stop();
    if (vpp_.state() != QProcess::NotRunning) {
        vpp_.kill();
        vpp_.waitForFinished(1000);
    }
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
    dpdkSource = args.contains("--pcap") ? "PCAP" : args.contains("--inline") ? "inline" : "live";
    if (args.contains("--no-events"))
        dpdkSource = args.contains("--pcap") ? "PCAP-probe" : "probe";
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
    if (dpdk_.state() == QProcess::NotRunning)
        return;
    dpdk_.terminate();
    QTimer::singleShot(3000, &dpdk_, [this] {
        if (dpdk_.state() != QProcess::NotRunning)
            dpdk_.kill();
    });
}

void Engines::pollVpp(const QString &socket) {
    if (vpp_.state() != QProcess::NotRunning)
        return;
    vppSocket_ = socket.trimmed().isEmpty() ? QStringLiteral("/run/vpp/cli.sock") : socket.trimmed();
    auto bin = QStandardPaths::findExecutable("vppctl");
    if (bin.isEmpty()) {
        vppConnected = false;
        vppStatus = "vppctl не установлен";
        emit changed();
        return;
    }
    if (!vppConnected)
        vppStatus = "Подключение…";
    vpp_.start(bin, {"-s", vppSocket_, "show", "hardware-interfaces"});
    vppTimeout_.start(5000);
    emit changed();
}
} // namespace siem
