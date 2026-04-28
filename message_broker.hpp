#pragma once
#include <string>
#include <queue>
#include <mutex>
#include <thread>
#include <atomic>
#include <condition_variable>

#include "secure_protocol.hpp"
#include "network_client.hpp"
#include "ipc_server.hpp"
#include "protocol.hpp"

class MessageBroker {
public:
    MessageBroker() : isRunning(false), isNetworkConnected(false), isIpcConnected(false) {}
    ~MessageBroker() { Stop(); }

    void SetNetworkStatus(bool status) { isNetworkConnected = status; }
    void SetIpcStatus(bool status) { isIpcConnected = status; ipcCv.notify_all(); }

    void Start(NetworkClient& netClient, IPCServer& ipcServer) {
        isRunning = true;

        wsThread = std::thread([this, &netClient]() {
            while (isRunning) {
                std::string msg;
                {
                    std::unique_lock<std::mutex> lock(wsMutex);
                    wsCv.wait(lock, [this] { return !wsQueue.empty() || !isRunning; });
                    if (!isRunning) break;
                    msg = wsQueue.front();
                    wsQueue.pop();
                }
                if (!msg.empty() && isNetworkConnected) netClient.Send(msg);
            }
            });

        ipcThread = std::thread([this, &ipcServer]() {
            while (isRunning) {
                CH_Packet pkt;
                {
                    std::unique_lock<std::mutex> lock(ipcMutex);
                    ipcCv.wait(lock, [this] { return (!ipcQueue.empty() && isIpcConnected) || !isRunning; });
                    if (!isRunning) break;
                    pkt = ipcQueue.front();
                    ipcQueue.pop();
                }
                ipcServer.SendPacket(pkt);
            }
            });
    }

    void PushToWS(CheatHaram::C2S_Message msg) {
        std::string securePayload = SecureProtocol::Pack(msg);
        if (!securePayload.empty()) {
            std::lock_guard<std::mutex> lock(wsMutex);
            wsQueue.push(securePayload);
            wsCv.notify_one();
        }
    }

    void PushToIPC(const CH_Packet& pkt) {
        std::lock_guard<std::mutex> lock(ipcMutex);
        ipcQueue.push(pkt);
        ipcCv.notify_one();
    }

    void Stop() {
        if (isRunning) {
            isRunning = false;
            wsCv.notify_all();
            ipcCv.notify_all();
            if (wsThread.joinable()) wsThread.join();
            if (ipcThread.joinable()) ipcThread.join();
        }
    }

private:
    std::queue<std::string> wsQueue;
    std::queue<CH_Packet> ipcQueue;
    std::mutex wsMutex, ipcMutex;
    std::condition_variable wsCv, ipcCv;
    std::thread wsThread, ipcThread;
    std::atomic<bool> isRunning;
    std::atomic<bool> isNetworkConnected;
    std::atomic<bool> isIpcConnected;
};