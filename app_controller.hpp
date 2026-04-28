#pragma once
#include <string>
#include <thread>
#include <algorithm>
#include <cctype>
#include <utility>
#include "event_bus.hpp"
#include "session_context.hpp"
#include "message_broker.hpp"
#include "ipc_server.hpp"
#include "integrity_scanner.hpp"
#include "downloader.hpp"
#include "injector.hpp"
#include "constants.hpp"
#include "dll_integrity.hpp"
#include "crypto.hpp"

class AppController {
private:
    struct ScopedFileDeleter {
        std::string filepath;
        ~ScopedFileDeleter() {
            if (!filepath.empty()) {
                DeleteFileA(filepath.c_str());
            }
        }
    };

public:
    static void Register(EventBus& bus, SessionContext& ctx, MessageBroker& broker, IPCServer& ipc, const std::string& root, const std::string& exe) {

        bus.Subscribe(EventType::AUTH_SUCCESS, [&bus](const Event&) {
            bus.Publish({ EventType::UI_STATUS_UPDATE, std::make_pair(UiStatusType::SUCCESS, std::string(PCrypt("Authenticated").c_str())) });
            });

        bus.Subscribe(EventType::WHITELIST_RECEIVED, [&bus](const Event&) {
            bus.Publish({ EventType::UI_STATUS_UPDATE, std::make_pair(UiStatusType::LOADING, std::string(PCrypt("Verifying Files...").c_str())) });
            bus.Publish({ EventType::START_SCAN, std::monostate{} });
            });

        bus.Subscribe(EventType::START_SCAN, [&bus, &ctx, root](const Event&) {
            std::thread([&bus, &ctx, root]() {
                ScanReport report = IntegrityScanner::VerifyGameFolder(root, ctx.GetWhitelist());

                switch (report.result) {
                case ScanResult::CLEAN:
                    bus.Publish({ EventType::SCAN_COMPLETED, std::monostate{} });
                    break;
                case ScanResult::INVALID_PATH:
                    bus.Publish({ EventType::SCAN_FAILED, std::string(PCrypt("Invalid game path.").c_str()) });
                    break;
                case ScanResult::HACK_DETECTED:
                    bus.Publish({ EventType::SCAN_FAILED, report.detectedFile });
                    break;
                }
                }).detach();
            });

        bus.Subscribe(EventType::SCAN_FAILED, [&bus](const Event& e) {
            std::string detectedFile = std::get<std::string>(e.payload);
            bus.Publish({ EventType::UI_STATUS_UPDATE, std::make_pair(UiStatusType::ERROR_STATE, std::string(PCrypt("Detected: ").c_str()) + detectedFile) });
            std::thread([&bus]() {
                std::this_thread::sleep_for(std::chrono::seconds(3));
                bus.Publish({ EventType::SHUTDOWN_REQUESTED, std::monostate{} });
                }).detach();
            });

        bus.Subscribe(EventType::SCAN_COMPLETED, [&bus, &ctx, &broker](const Event&) {
            if (ctx.isInjected) {
                broker.PushToIPC(PacketBuilder::CreateEmpty(CH_CMD_REQUEST_STATE));
            }
            else {
                bus.Publish({ EventType::UI_STATUS_UPDATE, std::make_pair(UiStatusType::SUCCESS, std::string(PCrypt("Starting Game...").c_str())) });
                bus.Publish({ EventType::INJECT_PAYLOAD, std::monostate{} });
            }
            });

        bus.Subscribe(EventType::INJECT_PAYLOAD, [&bus, &ctx, exe, root](const Event&) {
            std::thread([&bus, &ctx, exe, root]() {

                if (Injector::GetProcessIdByName(Constants::TargetExe().c_str()) != 0) {
                    bus.Publish({ EventType::UI_STATUS_UPDATE, std::make_pair(UiStatusType::ERROR_STATE, std::string(PCrypt("Error: Game already running! Close it first.").c_str())) });
                    std::this_thread::sleep_for(std::chrono::seconds(3));
                    bus.Publish({ EventType::SHUTDOWN_REQUESTED, std::monostate{} });
                    return;
                }

                std::string targetPathStr = root + "\\" + ctx.GetDllName();
                const char* p = targetPathStr.c_str();

                bus.Publish({ EventType::UI_STATUS_UPDATE, std::make_pair(UiStatusType::LOADING, std::string(PCrypt("Downloading Payload...").c_str())) });

                if (Downloader::DownloadHttps(ctx.GetDllUrl(), p)) {

                    ScopedFileDeleter cleaner{ targetPathStr };

                    std::string expectedHash = ctx.GetDllHash();
                    std::string actualHash = Crypto::CalculateSHA256File(p);

                    bool hashMatches = false;
                    if (expectedHash.length() == actualHash.length() && !expectedHash.empty()) {
                        hashMatches = std::equal(expectedHash.begin(), expectedHash.end(), actualHash.begin(),
                            [](char a, char b) { return std::tolower(a) == std::tolower(b); });
                    }

                    if (hashMatches) {
                        bus.Publish({ EventType::UI_STATUS_UPDATE, std::make_pair(UiStatusType::LOADING, std::string(PCrypt("Injecting...").c_str())) });

                        DWORD pid = Injector::LaunchAndInject(exe, p);

                        if (pid != 0) {
                            ctx.gamePid = pid;
                            bus.Publish({ EventType::INJECTION_SUCCESS, std::monostate{} });
                        }
                        else {
                            bus.Publish({ EventType::UI_STATUS_UPDATE, std::make_pair(UiStatusType::ERROR_STATE, std::string(PCrypt("Injection Failed.").c_str())) });
                            std::this_thread::sleep_for(std::chrono::seconds(3));
                            bus.Publish({ EventType::SHUTDOWN_REQUESTED, std::monostate{} });
                        }
                    }
                    else {
                        bus.Publish({ EventType::UI_STATUS_UPDATE, std::make_pair(UiStatusType::ERROR_STATE, std::string(PCrypt("Error: Payload Hash Mismatch!").c_str())) });
                        std::this_thread::sleep_for(std::chrono::seconds(3));
                        bus.Publish({ EventType::SHUTDOWN_REQUESTED, std::monostate{} });
                    }
                }
                else {
                    bus.Publish({ EventType::UI_STATUS_UPDATE, std::make_pair(UiStatusType::ERROR_STATE, std::string(PCrypt("Download Failed.").c_str())) });
                    std::this_thread::sleep_for(std::chrono::seconds(3));
                    bus.Publish({ EventType::SHUTDOWN_REQUESTED, std::monostate{} });
                }
                }).detach();
            });

        bus.Subscribe(EventType::INJECTION_SUCCESS, [&bus, &ctx](const Event&) {
            ctx.isInjected = true;
            DWORD activePid = ctx.gamePid.load();

            DllIntegrity::Start(activePid, ctx.GetDllName());

            std::thread([&bus, &ctx, activePid]() {
                while (Injector::IsProcessRunning(activePid)) {
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                }

                DllIntegrity::Stop();
                ctx.isInjected = false;
                ctx.gamePid = 0;
                bus.Publish({ EventType::SHUTDOWN_REQUESTED, std::monostate{} });
                }).detach();
            });
    }
};