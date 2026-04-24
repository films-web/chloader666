#pragma once
#include <string>
#include <thread>
#include "event_bus.hpp"
#include "session_context.hpp"
#include "message_broker.hpp"
#include "ipc_server.hpp"
#include "integrity_scanner.hpp"
#include "downloader.hpp"
#include "injector.hpp"
#include "constants.hpp"
#include "dll_integrity.hpp"

class AppController {
public:
    static void Register(EventBus& bus, SessionContext& ctx, MessageBroker& broker, IPCServer& ipc, const std::string& root, const std::string& exe) {

        bus.Subscribe(EventType::AUTH_SUCCESS, [&bus, &ctx](const Event&) {
            bus.Publish({ EventType::UI_STATUS_UPDATE, std::string(PCrypt("Verifying Files...").c_str()) });
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
            bus.Publish({ EventType::UI_STATUS_UPDATE, std::string(PCrypt("Detected: ").c_str()) + detectedFile });
            std::thread([&bus]() {
                std::this_thread::sleep_for(std::chrono::seconds(3));
                bus.Publish({ EventType::SHUTDOWN_REQUESTED, std::monostate{} });
                }).detach();
            });

        bus.Subscribe(EventType::SCAN_COMPLETED, [&bus](const Event&) {
            bus.Publish({ EventType::UI_STATUS_UPDATE, std::string(PCrypt("Ready. Waiting for Game...").c_str()) });
            bus.Publish({ EventType::INJECT_PAYLOAD, std::monostate{} });
            });

        bus.Subscribe(EventType::INJECT_PAYLOAD, [&bus, &ctx, exe](const Event&) {
            std::thread([&bus, &ctx, exe]() {
                while (Injector::GetProcessIdByName(Constants::TargetExe().c_str()) != 0) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                }

                char p[MAX_PATH];
                GetFullPathNameA(ctx.GetDllName().c_str(), MAX_PATH, p, nullptr);

                if (Downloader::DownloadHttps(ctx.GetDllUrl(), p) && Injector::LaunchAndInject(exe, p)) {
                    DeleteFileA(p);
                    bus.Publish({ EventType::INJECTION_SUCCESS, std::monostate{} });
                }
                else {
                    bus.Publish({ EventType::UI_STATUS_UPDATE, std::string(PCrypt("Injection Failed.").c_str()) });
                }
                }).detach();
            });

        bus.Subscribe(EventType::INJECTION_SUCCESS, [&bus, &ctx](const Event&) {
            bus.Publish({ EventType::UI_STATUS_UPDATE, std::string(PCrypt("Active.").c_str()) });
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