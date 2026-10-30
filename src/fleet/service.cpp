#include "service.h"
#include <QCoreApplication>
#include <QTimer>
#include <atomic>
#include <csignal>
#ifdef Q_OS_WIN
#include <windows.h>
#endif
namespace siem::fleet {
static std::atomic_bool stopping{false};
#ifdef Q_OS_WIN
static SERVICE_STATUS_HANDLE handle = nullptr;
static std::function<int()> serviceRun;
static std::wstring serviceName;
static int serviceExit = 0;
static void status(DWORD state, DWORD error = NO_ERROR) {
    if (!handle)
        return;
    SERVICE_STATUS s{};
    s.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    s.dwCurrentState = state;
    s.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
    s.dwWin32ExitCode = error;
    s.dwWaitHint = state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING ? 30000 : 0;
    SetServiceStatus(handle, &s);
}
static DWORD WINAPI control(DWORD event, DWORD, LPVOID, LPVOID) {
    if (event == SERVICE_CONTROL_STOP || event == SERVICE_CONTROL_SHUTDOWN) {
        stopping = true;
        status(SERVICE_STOP_PENDING);
        return NO_ERROR;
    }
    if (event == SERVICE_CONTROL_INTERROGATE)
        return NO_ERROR;
    return ERROR_CALL_NOT_IMPLEMENTED;
}
static void WINAPI serviceMain(DWORD, LPWSTR *) {
    handle = RegisterServiceCtrlHandlerExW(serviceName.c_str(), control, nullptr);
    if (!handle) {
        serviceExit = 1;
        return;
    }
    status(SERVICE_START_PENDING);
    serviceExit = serviceRun();
    status(SERVICE_STOPPED, serviceExit ? ERROR_SERVICE_SPECIFIC_ERROR : NO_ERROR);
}
#endif
void serviceReady() {
#ifdef Q_OS_WIN
    status(SERVICE_RUNNING);
#endif
}
void installStopHandlers() {
    std::signal(SIGINT, [](int) { stopping = true; });
    std::signal(SIGTERM, [](int) { stopping = true; });
    auto *timer = new QTimer(QCoreApplication::instance());
    QObject::connect(timer, &QTimer::timeout, [] {
        if (stopping)
            QCoreApplication::quit();
    });
    timer->start(250);
}
int runService(int argc, char **argv, const QString &name, const std::function<int()> &run) {
#ifdef Q_OS_WIN
    bool service = false;
    for (int n = 1; n < argc; ++n)
        if (QString::fromLocal8Bit(argv[n]) == "--service")
            service = true;
    if (service) {
        serviceRun = run;
        serviceName = name.toStdWString();
        SERVICE_TABLE_ENTRYW table[] = {{serviceName.data(), serviceMain}, {nullptr, nullptr}};
        return StartServiceCtrlDispatcherW(table) ? serviceExit : 1;
    }
#else
    Q_UNUSED(argc);
    Q_UNUSED(argv);
    Q_UNUSED(name);
#endif
    return run();
}
} // namespace siem::fleet
