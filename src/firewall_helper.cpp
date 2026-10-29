#include "core/firewall.h"
#include <QCoreApplication>
#include <QFile>
#include <QJsonDocument>
#include <QProcess>
#include <QTextStream>
#ifdef Q_OS_WIN
#include <windows.h>

#include <functional>
#include <netfw.h>
#endif
using namespace siem;
#ifdef Q_OS_WIN
static int applyWindows(const QJsonArray &rules) {
    // All COM calls are checked. Only the application's own rule group is managed.
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr))
        return 10;
    INetFwPolicy2 *policy = nullptr;
    INetFwRules *collection = nullptr;
    hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2),
                          reinterpret_cast<void **>(&policy));
    if (FAILED(hr)) {
        CoUninitialize();
        return 11;
    }
    hr = policy->get_Rules(&collection);
    if (FAILED(hr)) {
        policy->Release();
        CoUninitialize();
        return 12;
    }
    auto stringSet = [](const QString &s, auto setter) {
        BSTR b = SysAllocString(reinterpret_cast<const wchar_t *>(s.utf16()));
        auto result = setter(b);
        SysFreeString(b);
        return result;
    };
    // Fixed names bound the namespace. No changes to profiles or default OS policy.
    for (int i = 0; i < 1000; ++i) {
        QString name = QString("SentinelSIEM-%1").arg(i);
        const auto removed = stringSet(name, [&](BSTR b) { return collection->Remove(b); });
        if (FAILED(removed)) {
            collection->Release();
            policy->Release();
            CoUninitialize();
            return 15;
        }
    }
    int index = 0, code = 0;
    for (auto v : rules) {
        auto r = v.toObject();
        if (!r["enabled"].toBool(true))
            continue;
        INetFwRule *rule = nullptr;
        hr = CoCreateInstance(__uuidof(NetFwRule), nullptr, CLSCTX_INPROC_SERVER, __uuidof(INetFwRule),
                              reinterpret_cast<void **>(&rule));
        if (FAILED(hr)) {
            code = 13;
            break;
        }
        auto checked = [&](HRESULT result) {
            if (FAILED(result))
                code = 14;
        };
        checked(
            stringSet(QString("SentinelSIEM-%1").arg(index++), [&](BSTR b) { return rule->put_Name(b); }));
        checked(stringSet(r["name"].toString(), [&](BSTR b) { return rule->put_Description(b); }));
        checked(stringSet("SentinelSIEM", [&](BSTR b) { return rule->put_Grouping(b); }));
        const auto proto = r["protocol"].toString();
        long protocol = proto == "tcp" ? 6 : proto == "udp" ? 17 : 256;
        checked(rule->put_Protocol(protocol));
        bool inbound = r["direction"] == "input";
        checked(rule->put_Direction(inbound ? NET_FW_RULE_DIR_IN : NET_FW_RULE_DIR_OUT));
        auto local = r[inbound ? "destination" : "source"].toString();
        auto remote = r[inbound ? "source" : "destination"].toString();
        checked(stringSet(local == "any" ? "*" : local, [&](BSTR b) { return rule->put_LocalAddresses(b); }));
        checked(
            stringSet(remote == "any" ? "*" : remote, [&](BSTR b) { return rule->put_RemoteAddresses(b); }));
        if (protocol == 6 || protocol == 17) {
            const auto localPorts = firewallPorts(r, !inbound), remotePorts = firewallPorts(r, inbound);
            checked(stringSet(localPorts == "any" ? "*" : localPorts,
                              [&](BSTR b) { return rule->put_LocalPorts(b); }));
            checked(stringSet(remotePorts == "any" ? "*" : remotePorts,
                              [&](BSTR b) { return rule->put_RemotePorts(b); }));
        }
        checked(rule->put_Profiles(NET_FW_PROFILE2_ALL));
        checked(rule->put_Action(r["action"] == "drop" ? NET_FW_ACTION_BLOCK : NET_FW_ACTION_ALLOW));
        checked(rule->put_Enabled(VARIANT_TRUE));
        if (!code)
            checked(collection->Add(rule));
        rule->Release();
        if (code)
            break;
    }
    collection->Release();
    policy->Release();
    CoUninitialize();
    return code;
}
#endif
int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    auto args = app.arguments();
    QTextStream err(stderr);
    if (args.size() != 3 || args[1] != "--apply") {
        err << "Usage: siem-firewall-helper --apply policy.json\n";
        return 2;
    }
    QFile f(args[2]);
    if (!f.open(QIODevice::ReadOnly) || f.size() > 2 * 1024 * 1024) {
        err << "Cannot read policy (max 2 MiB)\n";
        return 2;
    }
    QJsonParseError parse;
    auto doc = QJsonDocument::fromJson(f.readAll(), &parse);
    if (parse.error != QJsonParseError::NoError || (!doc.isArray() && !doc.isObject())) {
        err << "Expected JSON policy object or legacy array\n";
        return 2;
    }
    QString error;
    auto configuration =
        normalizeFirewallPolicy(doc.isArray() ? QJsonValue(doc.array()) : QJsonValue(doc.object()), &error);
#ifdef Q_OS_WIN
    if (error.isEmpty())
        error = validateWindowsPolicy(configuration);
#else
    QString script;
    if (error.isEmpty())
        script = compileNftPolicy(configuration, &error);
#endif
    if (!error.isEmpty()) {
        err << error << '\n';
        return 2;
    }
#ifdef Q_OS_WIN
    return applyWindows(configuration["rules"].toArray());
#elif defined(Q_OS_LINUX)
    QString nft = QFile::exists("/usr/sbin/nft") ? "/usr/sbin/nft" : "/usr/bin/nft";
    auto run = [&](bool check) {
        QProcess p;
        auto env = QProcessEnvironment::systemEnvironment();
        env.remove("LD_PRELOAD");
        env.remove("LD_LIBRARY_PATH");
        p.setProcessEnvironment(env);
        p.start(nft, check ? QStringList{"--check", "-f", "-"} : QStringList{"-f", "-"});
        if (!p.waitForStarted(5000)) {
            err << p.errorString();
            return false;
        }
        p.write(script.toUtf8());
        p.closeWriteChannel();
        if (!p.waitForFinished(15000)) {
            p.kill();
            p.waitForFinished();
            err << "nft timed out\n";
            return false;
        }
        err << p.readAllStandardError();
        return p.exitStatus() == QProcess::NormalExit && p.exitCode() == 0;
    };
    if (!run(true))
        return 3;
    if (!run(false))
        return 4;
    QTextStream(stdout) << "Applied to inet sentinel_siem\n";
    return 0;
#else
    err << "Unsupported platform\n";
    return 2;
#endif
}
