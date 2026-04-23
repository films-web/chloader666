#pragma once
#include <string>
#include <thread>

#pragma warning(push, 0)
#include "json.hpp"
#pragma warning(pop)

#include "session_context.hpp"
#include "message_broker.hpp"
#include "ipc_server.hpp"
#include "integrity_scanner.hpp"
#include "downloader.hpp"
#include "injector.hpp"
#include "constants.hpp"
#include "dll_integrity.hpp"

enum class AppState { WAITING_AUTH, SCANNING, INJECTING, MONITORING, ERROR_STATE };

class AppController {
public:
    static void Run(SessionContext& ctx, MessageBroker& broker, IPCServer& ipc, const std::string& root, const std::string& exe) {
        AppState state = AppState::WAITING_AUTH;
        while (ctx.isRunning) {
            switch (state) {
            case AppState::WAITING_AUTH:
                if (ctx.isAuthenticated) { ctx.SetUiStatus(PCrypt("Verifying Files...").c_str()); state = AppState::SCANNING; }
                break;
            case AppState::SCANNING: {
                std::string res = IntegrityScanner::VerifyGameFolder(root, ctx.GetWhitelist());
                if (!res.empty()) { ctx.SetUiStatus((PCrypt("Detected: ").c_str() + res).c_str()); state = AppState::ERROR_STATE; }
                else { ctx.SetUiStatus(PCrypt("Ready.").c_str()); state = AppState::INJECTING; }
                break;
            }
            case AppState::INJECTING:
                if (Injector::GetProcessIdByName(Constants::TargetExe().c_str()) == 0) {
                    char p[MAX_PATH]; GetFullPathNameA(ctx.GetDllName().c_str(), MAX_PATH, p, nullptr);
                    if (Downloader::DownloadHttps(ctx.GetDllUrl(), p) && Injector::LaunchAndInject(exe, p)) {
                        DeleteFileA(p); ctx.SetUiStatus(PCrypt("Active.").c_str());
                        DllIntegrity::Start(Injector::GetProcessIdByName(Constants::TargetExe().c_str()), ctx.GetDllName());
                        state = AppState::MONITORING;
                    }
                }
                break;
            case AppState::MONITORING:
                if (Injector::GetProcessIdByName(Constants::TargetExe().c_str()) == 0) { DllIntegrity::Stop(); ctx.isRunning = false; }
                break;
            case AppState::ERROR_STATE:
                std::this_thread::sleep_for(std::chrono::seconds(3)); ctx.isRunning = false;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
};