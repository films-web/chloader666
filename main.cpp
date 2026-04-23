#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <filesystem>
#include <thread>
#include <chrono>

#include "constants.hpp"
#include "session_context.hpp"
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

static void DisableDebugging(SessionContext& ctx) {
    std::thread([&ctx]() {
        while (ctx.isRunning) {
            if (IsDebuggerPresent()) {
                TerminateProcess(GetCurrentProcess(), 0xDEAD);
            }

            BOOL isRemoteDebuggerPresent = FALSE;
            CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemoteDebuggerPresent);
            if (isRemoteDebuggerPresent) {
                TerminateProcess(GetCurrentProcess(), 0xDEAD);
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
        }).detach();
}

int main(int argc, char* argv[]) {
    SelfIntegrity::Start();

    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_CURSOR_INFO cursorInfo;
    GetConsoleCursorInfo(out, &cursorInfo);
    cursorInfo.bVisible = false;
    SetConsoleCursorInfo(out, &cursorInfo);
    SetConsoleTitleA("CheatHaram");

    UrlLauncher::RegisterProtocol();

    SessionContext ctx;
    ctx.SetTargetServer(UrlLauncher::ParseArgument(argc, argv));

    if (UrlLauncher::ForwardIfAlreadyRunning(ctx.GetTargetServer())) {
        return 0;
    }

    DisableDebugging(ctx);

    std::thread uiThread(ConsoleUI::Run, std::ref(ctx));

    std::string hardwareId = HWIDManager::Generate();

    std::string generatedSignature = Crypto::GenerateHMACSHA256(
        hardwareId,
        PCrypt("baf0f0e65f1b2688b8d99cb628d21c9a07e8992174fe2f9cfc15cef7f92a6fb9").c_str()
    );

    IPCServer ipcServer;
    NetworkClient netClient;
    MessageBroker broker;

    std::thread urlThread = UrlLauncher::StartPrimaryListener(ctx, broker);

    char fullExePath[MAX_PATH];
    GetFullPathNameA(Constants::TargetExe(), MAX_PATH, fullExePath, nullptr);
    std::string gameRootFolder = std::filesystem::path(fullExePath).parent_path().string();

    NetworkCallbacks::Register(ctx, netClient, ipcServer, broker, hardwareId, generatedSignature, gameRootFolder);
    broker.Start(netClient, ipcServer);

    AppController::Run(ctx, broker, ipcServer, gameRootFolder, fullExePath);

    ctx.isRunning = false;
    SelfIntegrity::Stop();

    if (uiThread.joinable()) uiThread.join();
    if (urlThread.joinable()) urlThread.join();

    return 0;
}