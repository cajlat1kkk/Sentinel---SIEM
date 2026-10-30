#include "policy.h"
#include "core/firewall.h"
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QLockFile>
#include <QThread>

namespace siem::fleet {
static QString stateFile(const QJsonObject &c) { return QDir(c["state_dir"].toString()).filePath("policy-state.json"); }
static QJsonObject readState(const QJsonObject &c) { return QFile::exists(stateFile(c)) ? readObject(stateFile(c)) : QJsonObject{}; }
static void saveState(const QJsonObject &c,const QJsonObject &s) { writePrivate(stateFile(c),QJsonDocument(s).toJson()); }
static QJsonObject nativePolicy(const QJsonObject &p) { return p["firewall"].toObject().value(nativeBackend()).toObject(defaultFirewallPolicy()); }
QString PolicyController::firewallHelper() {
    return QDir(QCoreApplication::applicationDirPath()).filePath(
#ifdef Q_OS_WIN
        "siem-firewall-helper.exe"
#else
        "siem-firewall-helper"
#endif
    );
}
PolicyController::PolicyController(const QJsonObject &c,const QString &path,QObject *parent)
    : QObject(parent),config_(c),configPath_(path),statePath_(stateFile(c)),directory_(c["state_dir"].toString()) {
    timeout_.setSingleShot(true);
    connect(&timeout_,&QTimer::timeout,&process_,[this] { process_.kill(); });
    auto finish=[this](bool success,const QString &error) {
        timeout_.stop();
        try {
            QLockFile lock(directory_+"/policy.lock"); require(lock.tryLock(0),"Policy state busy");
            auto s=state(); auto pending=s["pending"].toObject();
            if(pending.isEmpty()) return;
            if(success) { pending["applied"]=true; s["pending"]=pending; s["error"]=""; save(s); }
            else { s["error"]=error; save(s); /* independent watchdog restores the previous policy */ }
            emit changed();
        } catch(const std::exception &e) { qWarning("Policy completion: %s",e.what()); }
    };
    connect(&process_,&QProcess::finished,this,[this,finish](int code,QProcess::ExitStatus status) {
        finish(code==0 && status==QProcess::NormalExit,QString::fromUtf8(process_.readAllStandardError()).left(2048));
    });
    connect(&process_,&QProcess::errorOccurred,this,[finish](QProcess::ProcessError error) { if(error==QProcess::FailedToStart) finish(false,"Firewall helper failed to start"); });
}
QJsonObject PolicyController::state() const { return readState(config_); }
void PolicyController::save(const QJsonObject &s) const { saveState(config_,s); }
QJsonObject PolicyController::activePolicy() const { return state()["active"].toObject().value("policy").toObject(defaultEndpointPolicy()); }
QJsonObject PolicyController::health() const {
    const auto s=state(); const auto pending=s["pending"].toObject();
    return {{"policy_token",pending.isEmpty() ? s["active"].toObject()["token"].toString() : pending["token"].toString()},
            {"policy_state",!pending.isEmpty() ? pending["applied"].toBool() ? "pending" : "applying" : s["error"].toString().isEmpty() ? "confirmed" : "error"},
            {"policy_error",s["error"].toString()}, {"manage_firewall",config_["manage_firewall"].toBool(false)}};
}
bool PolicyController::applyBlocking(const QJsonObject &policy,const QString &directory,QString *error) {
    const auto file=directory+"/restore-policy.json";
    writePrivate(file,QJsonDocument(nativePolicy(policy)).toJson());
    QProcess p; p.start(firewallHelper(),{"--apply",file});
    if(!p.waitForStarted(3000) || !p.waitForFinished(20000)) { p.kill(); p.waitForFinished(3000); *error="Firewall restore timed out or helper unavailable"; return false; }
    *error=QString::fromUtf8(p.readAllStandardError()).left(2048);
    return p.exitStatus()==QProcess::NormalExit && p.exitCode()==0;
}
void PolicyController::rollback(const QJsonObject &config,const QString &token) {
    const auto directory=config["state_dir"].toString();
    QLockFile lock(directory+"/policy.lock"); require(lock.tryLock(3000),"Policy state busy during rollback");
    auto s=readState(config); const auto pending=s["pending"].toObject();
    if(pending.isEmpty() || pending["token"].toString()!=token) return;
    QString error;
    if(applyBlocking(s["active"].toObject().value("policy").toObject(defaultEndpointPolicy()),directory,&error)) {
        s["failed_token"]=token; s.remove("pending"); s["error"]="Policy rolled back: server confirmation was not received";
    } else s["error"]="Rollback failed; retrying on restart: "+error;
    saveState(config,s);
}
void PolicyController::recover() {
    auto s=state();
    if(!s["pending"].toObject().isEmpty()) {
        require(config_["manage_firewall"].toBool(),"Pending firewall operation exists: restore with manage_firewall enabled");
        rollback(config_,s["pending"].toObject()["token"].toString());
        require(state()["pending"].toObject().isEmpty(),"Firewall rollback failed");
    } else if(config_["manage_firewall"].toBool() && s["active"].toObject()["policy"].toObject()["firewall"].toObject().contains(nativeBackend())) {
        QString error;
        const bool ok=applyBlocking(activePolicy(),directory_,&error);
        s["error"]=ok ? QString() : "Startup firewall restore failed: "+error;
        save(s);
    }
}
void PolicyController::accept(const QJsonObject &desired,const QString &confirmation) {
    if(process_.state()!=QProcess::NotRunning) return;
    QLockFile lock(directory_+"/policy.lock"); require(lock.tryLock(0),"Policy state busy");
    auto s=state(); auto pending=s["pending"].toObject();
    if(!pending.isEmpty()) {
        if(pending["applied"].toBool() && confirmation==pending["token"].toString() && confirmation==desired["token"].toString() &&
           QDateTime::fromString(pending["deadline"].toString(),Qt::ISODateWithMs)>QDateTime::currentDateTimeUtc()) {
            s["active"]=QJsonObject{{"token",pending["token"]},{"policy",pending["policy"]}};
            s.remove("pending"); s["error"]=""; save(s); emit changed();
        }
        return;
    }
    auto token=desired["token"].toString();
    require(!token.isEmpty() && token.size()<=96,"Invalid policy version");
    if(token==s["active"].toObject()["token"].toString() || token==s["failed_token"].toString()) return;
    auto policy=desired["policy"].toObject(); auto error=validateEndpointPolicy(policy); require(error.isEmpty(),error);
    const bool firewallChanged=nativePolicy(policy)!=nativePolicy(activePolicy());
    if(firewallChanged && !config_["manage_firewall"].toBool(false)) {
        s["error"]="Remote firewall management is disabled in local agent configuration"; s["failed_token"]=token; save(s); emit changed(); return;
    }
    if(!firewallChanged) { s["active"]=QJsonObject{{"token",token},{"policy",policy}}; s["error"]=""; save(s); emit changed(); return; }
    lock.unlock(); apply(desired);
}
void PolicyController::apply(const QJsonObject &desired) {
    QLockFile lock(directory_+"/policy.lock"); require(lock.tryLock(0),"Policy state busy");
    auto s=state();
    auto pending=desired; pending["applied"]=false;
    pending["deadline"]=QDateTime::currentDateTimeUtc().addSecs(90).toString(Qt::ISODateWithMs);
    s["pending"]=pending; save(s);
    // Spawn before applying. This process survives a GUI/agent crash and has a bounded mandate.
    const bool started=QProcess::startDetached(QCoreApplication::applicationFilePath(),
        {"--config",configPath_,"--watchdog",desired["token"].toString()});
    if(!started) { s.remove("pending"); s["error"]="Cannot start rollback watchdog; policy was not applied"; save(s); return; }
    const auto file=directory_+"/candidate-policy.json";
    writePrivate(file,QJsonDocument(nativePolicy(desired["policy"].toObject())).toJson());
    process_.start(firewallHelper(),{"--apply",file}); timeout_.start(20000); emit changed();
}
int PolicyController::watchdog(const QJsonObject &config,const QString &token) {
    require(config["manage_firewall"].toBool(false),"Firewall management disabled");
    for(int n=0;n<120;++n) {
        const auto pending=readState(config)["pending"].toObject();
        if(pending.isEmpty() || pending["token"].toString()!=token) return 0;
        auto deadline=QDateTime::fromString(pending["deadline"].toString(),Qt::ISODateWithMs);
        require(deadline.isValid(),"Invalid policy deadline");
        if(deadline<=QDateTime::currentDateTimeUtc()) {
            rollback(config,token);
            return readState(config)["pending"].toObject().isEmpty() ? 0 : 1;
        }
        QThread::msleep(1000);
    }
    rollback(config,token); return 1;
}
}
