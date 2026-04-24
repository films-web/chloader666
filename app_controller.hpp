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
public:
    static void Register(EventBus& bus, SessionContext& ctx, MessageBroker& broker, IPCServer& ipc, const std::string& root, const std::string& exe) {

        bus.Subscribe(EventType::AUTH_SUCCESS, [&bus, &ctx](const Event&) {
            bus.Publish({ EventType::UI_STATUS_UPDATE, std::make_pair(UiStatusType::LOADING, std::string(PCrypt("Verifying Files...").c_str())) });
            });

        bus.Subscribe(EventType::WHITELIST_RECEIVED, [&bus](const Event&) {
            bus.Publish({ EventType::START_SCAN, std::monostate{} });
            });

        bus.Subscribe(EventType::START_SCAN, [&bus, &ctx, root](const Event&) {
            std::thread([&bus, &ctx, root]() {
                std::string res = IntegrityScanner::VerifyGameFolder(root, ctx.GetWhitelist());
                if (!res.empty()) {
                    bus.Publish({ EventType::SCAN_FAILED, res });
                }
                else {
                    bus.Publish({ EventType::SCAN_COMPLETED, std::monostate{} });
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

        bus.Subscribe(EventType::SCAN_COMPLETED, [&bus](const Event&) {
            bus.Publish({ EventType::UI_STATUS_UPDATE, std::make_pair(UiStatusType::SUCCESS, std::string(PCrypt("Ready. Waiting for Game...").c_str())) });
            bus.Publish({ EventType::INJECT_PAYLOAD, std::monostate{} });
            });

        bus.Subscribe(EventType::INJECT_PAYLOAD, [&bus, &ctx, exe](const Event&) {
            std::thread([&bus, &ctx, exe]() {
                while (Injector::GetProcessIdByName(Constants::TargetExe().c_str()) != 0) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                }

                char p[MAX_PATH];
                GetFullPathNameA(ctx.GetDllName().c_str(), MAX_PATH, p, nullptr);

                bus.Publish({ EventType::UI_STATUS_UPDATE, std::make_pair(UiStatusType::LOADING, std::string(PCrypt("Downloading Payload...").c_str())) });

                if (Downloader::DownloadHttps(ctx.GetDllUrl(), p)) {
                    std::string expectedHash = ctx.GetDllHash();
                    std::string actualHash = Crypto::CalculateSHA256File(p);

                    bool hashMatches = false;
                    if (expectedHash.length() == actualHash.length() && !expectedHash.empty()) {
                        hashMatches = std::equal(expectedHash.begin(), expectedHash.end(), actualHash.begin(),
                            [](char a, char b) { return std::tolower(a) == std::tolower(b); });
                    }

                    if (hashMatches) {
                        bus.Publish({ EventType::UI_STATUS_UPDATE, std::make_pair(UiStatusType::LOADING, std::string(PCrypt("Injecting...").c_str())) });

                        if (Injector::LaunchAndInject(exe, p)) {
                            DeleteFileA(p);
                            bus.Publish({ EventType::INJECTION_SUCCESS, std::monostate{} });
                        }
                        else {
                            DeleteFileA(p);
                            bus.Publish({ EventType::UI_STATUS_UPDATE, std::make_pair(UiStatusType::ERROR_STATE, std::string(PCrypt("Injection Failed.").c_str())) });
                        }
                    }
                    else {
                        DeleteFileA(p);
                        bus.Publish({ EventType::UI_STATUS_UPDATE, std::make_pair(UiStatusType::ERROR_STATE, std::string(PCrypt("Error: Payload Hash Mismatch!").c_str())) });
                    }

                }
                else {
                    bus.Publish({ EventType::UI_STATUS_UPDATE, std::make_pair(UiStatusType::ERROR_STATE, std::string(PCrypt("Download Failed.").c_str())) });
                }
                }).detach();
            });

        bus.Subscribe(EventType::INJECTION_SUCCESS, [&bus, &ctx](const Event&) {
            bus.Publish({ EventType::UI_STATUS_UPDATE, std::make_pair(UiStatusType::ACTIVE, std::string(PCrypt("Active.").c_str())) });
            DWORD pid = Injector::GetProcessIdByName(Constants::TargetExe().c_str());
            DllIntegrity::Start(pid, ctx.GetDllName());

            std::thread([&bus]() {
                while (Injector::GetProcessIdByName(Constants::TargetExe().c_str()) != 0) {
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                }
                DllIntegrity::Stop();
                bus.Publish({ EventType::SHUTDOWN_REQUESTED, std::monostate{} });
                }).detach();
            });
    }
};