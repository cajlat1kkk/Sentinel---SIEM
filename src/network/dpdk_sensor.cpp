#include "core/firewall.h"
#include "network/packet.h"
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QFile>
#include <QJsonDocument>
#include <QThread>
#include <csignal>
#include <cstdio>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_version.h>
#include <sched.h>
static volatile std::sig_atomic_t stopping = 0;
static void stop(int) {
    stopping = 1;
}
static void output(const QJsonObject &j) {
    auto b = QJsonDocument(j).toJson(QJsonDocument::Compact);
    std::fwrite(b.constData(), 1, size_t(b.size()), stdout);
    std::fputc('\n', stdout);
    std::fflush(stdout);
}
static int failure(const QString &s) {
    output({{"type", "error"}, {"message", s}});
    return 2;
}
int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    QStringList args = app.arguments(), eal;
    QString pcap, policy;
    bool bridge = false;
    int seconds = 0;
    for (int i = 1; i < args.size(); ++i) {
        if (args[i] == "--") {
            eal = args.mid(i + 1);
            break;
        }
        if (args[i] == "--inline") {
            bridge = true;
            continue;
        }
        if (args[i] == "--pcap" && i + 1 < args.size()) {
            pcap = args[++i];
            continue;
        }
        if (args[i] == "--policy" && i + 1 < args.size()) {
            policy = args[++i];
            continue;
        }
        if (args[i] == "--seconds" && i + 1 < args.size()) {
            bool ok;
            seconds = args[++i].toInt(&ok);
            if (!ok || seconds < 0)
                return failure("Invalid duration");
            continue;
        }
        return failure(
            "Usage: siem-dpdk [--pcap file] [--inline --policy rules.json] [--seconds N] -- EAL arguments");
    }
    QJsonArray rules;
    if (!policy.isEmpty()) {
        QFile f(policy);
        if (!f.open(QIODevice::ReadOnly) || f.size() > 1024 * 1024)
            return failure("Cannot read policy");
        auto d = QJsonDocument::fromJson(f.readAll());
        if (!d.isArray())
            return failure("Invalid policy JSON");
        rules = d.array();
        QString error;
        siem::compileNft(rules, &error);
        if (!error.isEmpty())
            return failure(error);
    }
    if (!pcap.isEmpty()) {
        if (bridge || pcap.contains(',') || !QFile::exists(pcap))
            return failure("PCAP must exist, must not contain commas; inline needs two live ports");
        cpu_set_t cpus;
        CPU_ZERO(&cpus);
        sched_getaffinity(0, sizeof(cpus), &cpus);
        int cpu = 0;
        while (cpu < CPU_SETSIZE && !CPU_ISSET(cpu, &cpus))
            ++cpu;
        eal = {"--lcores",
               QString("0@%1").arg(cpu),
               "--main-lcore",
               "0",
               "--no-huge",
               "--no-pci",
               "--no-shconf",
               "--no-telemetry",
               "--vdev=net_pcap0,rx_pcap=" + pcap};
    }
    if (eal.isEmpty())
        return failure("Explicit EAL arguments or --pcap are required; no automatic NIC binding");
    std::vector<QByteArray> storage;
    storage.push_back("siem-dpdk");
    for (const auto &s : eal)
        storage.push_back(s.toLocal8Bit());
    std::vector<char *> av;
    for (auto &s : storage)
        av.push_back(s.data());
    if (rte_eal_init(int(av.size()), av.data()) < 0)
        return failure(QString("DPDK EAL: %1").arg(rte_strerror(rte_errno)));
    std::vector<uint16_t> ports;
    uint16_t port;
    RTE_ETH_FOREACH_DEV(port) ports.push_back(port);
    if (ports.empty() || ports.size() > 16 || (bridge && ports.size() != 2)) {
        rte_eal_cleanup();
        return failure("Monitoring requires 1–16 ports; inline bridge requires exactly 2 ports");
    }
    auto *pool =
        rte_pktmbuf_pool_create("sentinel_pool", 8191, 128, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!pool) {
        rte_eal_cleanup();
        return failure("Cannot allocate mbuf pool");
    }
    std::vector<uint16_t> started;
    auto cleanup = [&] {
        for (auto p : started) {
            rte_eth_dev_stop(p);
            rte_eth_dev_close(p);
        }
        rte_mempool_free(pool);
        rte_eal_cleanup();
    };
    for (auto p : ports) {
        rte_eth_conf config{};
        rte_eth_dev_info info{};
        if (rte_eth_dev_info_get(p, &info) < 0 || rte_eth_dev_configure(p, 1, 1, &config) < 0) {
            cleanup();
            return failure("Port configuration failed");
        }
        uint16_t rx = 512, tx = 512;
        rte_eth_dev_adjust_nb_rx_tx_desc(p, &rx, &tx);
        int socket = rte_eth_dev_socket_id(p);
        if (socket < 0)
            socket = 0;
        if (rte_eth_rx_queue_setup(p, 0, rx, unsigned(socket), &info.default_rxconf, pool) < 0 ||
            rte_eth_tx_queue_setup(p, 0, tx, unsigned(socket), &info.default_txconf) < 0 ||
            rte_eth_dev_start(p) < 0) {
            rte_eth_dev_close(p);
            cleanup();
            return failure("Queue setup / port start failed");
        }
        started.push_back(p);
        rte_eth_promiscuous_enable(p);
    }
    std::signal(SIGINT, stop);
    std::signal(SIGTERM, stop);
    QElapsedTimer clock;
    clock.start();
    qint64 last = 0;
    quint64 packets = 0, bytes = 0, drops = 0, alerts = 0, suppressed = 0, tx = 0;
    int emitted = 0;
    output({{"type", "ready"},
            {"version", rte_version()},
            {"ports", int(ports.size())},
            {"mode", bridge ? "inline" : "monitor"}});
    while (!stopping && (seconds == 0 || clock.elapsed() < qint64(seconds) * 1000)) {
        unsigned received = 0;
        for (size_t index = 0; index < ports.size(); ++index) {
            rte_mbuf *burst[32];
            auto count = rte_eth_rx_burst(ports[index], 0, burst, 32);
            received += count;
            for (unsigned n = 0; n < count; ++n) {
                auto *m = burst[n];
                ++packets;
                bytes += rte_pktmbuf_pkt_len(m);
                int length = int(rte_pktmbuf_pkt_len(m));
                QByteArray copy(length, Qt::Uninitialized);
                const auto *data = rte_pktmbuf_read(m, 0, unsigned(length), copy.data());
                auto packet = data ? siem::inspectPacket(QByteArray(static_cast<const char *>(data), length))
                                   : siem::Packet{};
                bool blocked = bridge && siem::packetBlocked(packet, rules, true);
                if (!packet.signature.isEmpty())
                    ++alerts;
                if (packet.valid) {
                    if (emitted < 500) {
                        auto ev = siem::packetEvent(packet);
                        ev["blocked"] = blocked;
                        output(ev);
                        ++emitted;
                    } else
                        ++suppressed;
                }
                if (bridge && !blocked) {
                    auto sent = rte_eth_tx_burst(ports[1 - index], 0, &m, 1);
                    if (sent)
                        ++tx;
                    else {
                        ++drops;
                        rte_pktmbuf_free(m);
                    }
                } else {
                    if (blocked)
                        ++drops;
                    rte_pktmbuf_free(m);
                }
            }
        }
        if (clock.elapsed() - last >= 1000) {
            output({{"type", "stats"},
                    {"packets", double(packets)},
                    {"bytes", double(bytes)},
                    {"dropped", double(drops)},
                    {"alerts", double(alerts)},
                    {"forwarded", double(tx)},
                    {"suppressed", double(suppressed)},
                    {"elapsed_ms", double(clock.elapsed())}});
            last = clock.elapsed();
            emitted = 0;
        }
        if (!received)
            QThread::usleep(500);
    }
    output({{"type", "stats"},
            {"packets", double(packets)},
            {"bytes", double(bytes)},
            {"dropped", double(drops)},
            {"alerts", double(alerts)},
            {"forwarded", double(tx)},
            {"suppressed", double(suppressed)},
            {"elapsed_ms", double(clock.elapsed())}});
    cleanup();
    return 0;
}
