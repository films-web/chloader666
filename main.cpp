#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <filesystem>
#include <thread>
#include <chrono>
#include <mutex>
#include <condition_variable>

#include "constants.hpp"
#include "session_context.hpp"
#include "event_bus.hpp"
#include "crypto.hpp"
#include "hwid.hpp"
#include "console_ui.hpp"
#include "anti_debug.hpp"
#include "self_integrity.hpp"
#include "poly_crypt.hpp"
#include "ipc_server.hpp"
#include "network_client.hpp"
#include "message_broker.hpp"
#include "url_launcher.hpp"
#include "network_callbacks.hpp"
#include "app_controller.hpp"
#include "heartbeat_manager.hpp"

int main(int argc, char* argv[]) {
    // 1. Initialize UI - Hidden behind __forceinline
    ConsoleUI::Initialize();

    std::atomic<bool> globalRunning{ true };

    // 2. Protocol & Single Instance Handling
    // This allows the web dashboard to communicate with the loader
    UrlLauncher::RegisterProtocol();
    std::string targetServerArg = UrlLauncher::ParseArgument(argc, argv);

    if (UrlLauncher::ForwardIfAlreadyRunning(targetServerArg)) {
        // If an instance is already open, we forward the IP and exit
        return 0;
    }

    // 3. Start Security Guardrails
    SelfIntegrity::Start();             // Monitors for memory patching
    AntiDebug::Start(globalRunning);    // Monitors for debuggers/profilers

    // 4. Core System Components
    EventBus bus;
    SessionContext ctx;
    ctx.SetTargetServer(targetServerArg);

    std::mutex mainMutex;
    std::condition_variable mainCv;

    // Shutdown Handler: Ensures all threads close gracefully
    bus.Subscribe(EventType::SHUTDOWN_REQUESTED, [&globalRunning, &mainCv](const Event&) {
        globalRunning = false;
        mainCv.notify_all();
        });

    // Register UI to listen for status updates
    ConsoleUI::Register(bus, ctx);

    // 5. Identity & Signature Generation
    // Hardware ID tied to Client Secret for server-side verification
    std::string hardwareId = HWIDManager::Generate();
    std::string generatedSignature = Crypto::GenerateSHA256Key(
        hardwareId,
        Constants::ClientSecret().c_str()
    );

    // 6. Network & Communication Stack
    IPCServer ipcServer;
    NetworkClient netClient;
    MessageBroker broker;

    // 7. Path Discovery
    char loaderPath[MAX_PATH];
    GetModuleFileNameA(NULL, loaderPath, MAX_PATH);
    std::string gameRootFolder = std::filesystem::path(loaderPath).parent_path().string();

    // The EXE we are protecting
    std::string fullExePath = gameRootFolder + "\\" + std::string(Constants::TargetExe().c_str());

    // 8. Register the State Machine (The Brain)
    // This handles the transition from Auth -> Scan -> Inject
    AppController::Register(bus, ctx, broker, ipcServer, gameRootFolder, fullExePath);

    // 9. Extra IPC Handlers for URI Protocol
    bus.Subscribe(EventType::URL_CONNECT_REQUESTED, [&ctx, &broker](const Event& e) {
        std::string ip = std::get<std::string>(e.payload);
        ctx.SetTargetServer(ip);
        // Command the game client to connect to the new IP
        std::string cmd = std::string(PCrypt("connect ").c_str()) + ip + "\n";
        broker.PushToIPC(PacketBuilder::CreateString(CH_CMD_CONNECT_SERVER, cmd));
        });

    bus.Subscribe(EventType::CRASH_REQUESTED, [&broker](const Event&) {
        // Remote administrative kill-switch
        broker.PushToIPC(PacketBuilder::CreateEmpty(CH_CMD_CRASH_CLIENT));
        });

    // 10. Start Background Services
    std::thread urlThread = UrlLauncher::StartPrimaryListener(bus, globalRunning);

    // Connects Network Events to the ServerHandler logic
    NetworkCallbacks::Register(bus, ctx, netClient, ipcServer, broker, generatedSignature);

    // Fire up the message worker threads
    broker.Start(netClient, ipcServer);

    // Start the server proof-of-life pulse
    HeartbeatManager::Start(ctx, broker);

    // 11. Final Launch Sequence
    bus.Publish({ EventType::UI_STATUS_UPDATE,
        std::make_pair(UiStatusType::LOADING,
            std::string(PCrypt("Connecting to CheatHaram Cloud...").c_str())) });

    // This handles the event queue on the main thread
    bus.RunDispatcher();

    // 12. Wait for Shutdown Signal
    {
        std::unique_lock<std::mutex> lock(mainMutex);
        mainCv.wait(lock, [&globalRunning] { return !globalRunning.load(); });
    }

    HeartbeatManager::Stop();
    broker.Stop();
    netClient.Stop();
    ipcServer.Stop();
    SelfIntegrity::Stop();
    AntiDebug::Stop();

    if (urlThread.joinable()) urlThread.join();

    return 0;
}