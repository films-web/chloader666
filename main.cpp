#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <filesystem>
#include <thread>
#include <chrono>

#include "constants.hpp"
#include "session_context.hpp"
#include "event_bus.hpp"
#include "crypto.hpp"
#include "hwid.hpp"
#include "console_ui.hpp"
#include "self_integrity.hpp"
#include "poly_crypt.hpp"
#include "ipc_server.hpp"
#include "network_client.hpp"
#include "message_broker.hpp"
#include "url_launcher.hpp"
#include "network_callbacks.hpp"
#include "app_controller.hpp"
#include "heartbeat_manager.hpp"

static void DisableDebugging(std::atomic<bool>& isRunning) {
    std::thread([&isRunning]() {
        while (isRunning) {
            if (IsDebuggerPresent()) TerminateProcess(GetCurrentProcess(), 0xDEAD);
            BOOL isRemoteDebuggerPresent = FALSE;
            CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemoteDebuggerPresent);
            if (isRemoteDebuggerPresent) TerminateProcess(GetCurrentProcess(), 0xDEAD);
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
        }).detach();
}

int main(int argc, char* argv[]) {
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_CURSOR_INFO cursorInfo;
    GetConsoleCursorInfo(out, &cursorInfo);
    cursorInfo.bVisible = false;
    SetConsoleCursorInfo(out, &cursorInfo);
    SetConsoleTitleA("CheatHaram");

    UrlLauncher::RegisterProtocol();
    std::string targetServerArg = UrlLauncher::ParseArgument(argc, argv);

    if (UrlLauncher::ForwardIfAlreadyRunning(targetServerArg)) {
        return 0;
    }

    EventBus bus;
    SessionContext ctx;
    ctx.SetTargetServer(targetServerArg);

    std::atomic<bool> globalRunning{ true };
    std::mutex mainMutex;
    std::condition_variable mainCv;

    bus.Subscribe(EventType::SHUTDOWN_REQUESTED, [&globalRunning, &mainCv](const Event&) {
        globalRunning = false;
        mainCv.notify_all();
        });

    DisableDebugging(globalRunning);

    ConsoleUI::Register(bus, ctx);

    std::string hardwareId = HWIDManager::Generate();
    std::string generatedSignature = Crypto::GenerateHMACSHA256(
        hardwareId,
        PCrypt("baf0f0e65f1b2688b8d99cb628d21c9a07e8992174fe2f9cfc15cef7f92a6fb9").c_str()
    );

    IPCServer ipcServer;
    NetworkClient netClient;
    MessageBroker broker;

    char loaderPath[MAX_PATH];
    GetModuleFileNameA(NULL, loaderPath, MAX_PATH);
    std::string gameRootFolder = std::filesystem::path(loaderPath).parent_path().string();
    std::string fullExePath = gameRootFolder + "\\" + std::string(Constants::TargetExe().c_str());


    AppController::Register(bus, ctx, broker, ipcServer, gameRootFolder, fullExePath);

    bus.Subscribe(EventType::URL_CONNECT_REQUESTED, [&ctx, &broker](const Event& e) {
        std::string ip = std::get<std::string>(e.payload);
        ctx.SetTargetServer(ip);
        broker.PushToIPC(PacketBuilder::CreateString(CH_CMD_CONNECT_SERVER, "connect " + ip + "\n"));
        });

    bus.Subscribe(EventType::CRASH_REQUESTED, [&broker](const Event&) {
        broker.PushToIPC(PacketBuilder::CreateEmpty(CH_CMD_CRASH_CLIENT));
        });

    std::thread urlThread = UrlLauncher::StartPrimaryListener(bus, globalRunning);

    NetworkCallbacks::Register(bus, ctx, netClient, ipcServer, broker, hardwareId, generatedSignature);

    broker.Start(netClient, ipcServer);

    HeartbeatManager::Start(ctx, broker);

    SelfIntegrity::Start();

    bus.Publish({ EventType::UI_STATUS_UPDATE, std::make_pair(UiStatusType::LOADING, std::string(PCrypt("Connecting to Server...").c_str())) });

    bus.RunDispatcher();

    std::unique_lock<std::mutex> lock(mainMutex);
    mainCv.wait(lock, [&globalRunning] { return !globalRunning.load(); });

    HeartbeatManager::Stop();
    SelfIntegrity::Stop();
    netClient.Stop();
    broker.Stop();
    ipcServer.Stop();

    if (urlThread.joinable()) urlThread.join();

    return 0;
}