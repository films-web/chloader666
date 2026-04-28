#pragma once
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>

#include "messages.pb.h"

#include "session_context.hpp"
#include "message_broker.hpp"
#include "packet_builder.hpp"

class HeartbeatManager {
private:
    static inline std::thread hbThread;
    static inline std::mutex hbMutex;
    static inline std::condition_variable hbCv;
    static inline std::atomic<bool> isRunning{ false };

public:
    static void Start(SessionContext& ctx, MessageBroker& broker) {
        if (isRunning) return;
        isRunning = true;

        hbThread = std::thread([&ctx, &broker]() {
            std::unique_lock<std::mutex> lock(hbMutex);
            while (isRunning) {

                bool shutdownTriggered = hbCv.wait_for(lock, std::chrono::seconds(30), [] {
                    return !isRunning.load();
                    });

                if (shutdownTriggered) {
                    break;
                }

                if (ctx.isAuthenticated) {
                    CheatHaram::C2S_Message hbMsg;
                    hbMsg.set_action(CheatHaram::ActionType::HEARTBEAT);
                    broker.PushToWS(hbMsg);

                    if (ctx.isInjected && ctx.isGameConnected) {
                        broker.PushToIPC(PacketBuilder::CreateEmpty(CH_CMD_REQUEST_STATE));
                    }
                }
            }
            });
    }

    static void Stop() {
        if (isRunning) {
            isRunning = false;
            hbCv.notify_all();

            if (hbThread.joinable()) {
                hbThread.join();
            }
        }
    }
};