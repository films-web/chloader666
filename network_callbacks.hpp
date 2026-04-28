#pragma once
#include <string>
#include <utility>
#include "event_bus.hpp"
#include "session_context.hpp"
#include "network_client.hpp"
#include "message_broker.hpp"
#include "ipc_server.hpp"
#include "server_handler.hpp"
#include "ipc_handler.hpp"
#include "constants.hpp"
#include "poly_crypt.hpp"
#include "messages.pb.h"

namespace NetworkCallbacks {
    static __forceinline void Register(EventBus& bus, SessionContext& ctx, NetworkClient& netClient, IPCServer& ipcServer, MessageBroker& broker, const std::string& hardwareId,
        const std::string& signature) {

        netClient.Start(std::string(Constants::WsUrl().c_str()),
            [&bus, &broker, signature, hardwareId](bool isConnected, const std::string& errorMsg) {
                broker.SetNetworkStatus(isConnected);

                if (isConnected) {
                    bus.Publish({ EventType::UI_STATUS_UPDATE, std::make_pair(UiStatusType::LOADING, std::string(PCrypt("Authenticating...").c_str())) });
                    CheatHaram::C2S_Message authMsg;
                    authMsg.set_action(CheatHaram::ActionType::AUTH_REQUEST);
                    authMsg.set_hwid(hardwareId);
                    authMsg.set_signature(signature);

                    broker.PushToWS(authMsg);
                }
                else {
                    std::string msg = errorMsg.empty() ? std::string(PCrypt("Disconnected.").c_str()) : std::string(PCrypt("Net Error: ").c_str()) + errorMsg;
                    bus.Publish({ EventType::UI_STATUS_UPDATE, std::make_pair(UiStatusType::ERROR_STATE, msg) });
                    bus.Publish({ EventType::AUTH_FAILED, std::monostate{} });
                }
            },
            [&bus, &ctx, &broker](const std::string& msg) {
                ServerHandler::ProcessMessage(msg, bus, ctx, broker);
            }
        );

        ipcServer.Start(std::string(Constants::IpcPipeName().c_str()),
            [&broker, &bus](const CH_Packet& pkt) {
                IPCHandler::ProcessMessage(pkt, broker, bus);
            },
            [&ctx, &bus, &broker](bool isConnected) {
                ctx.isGameConnected = isConnected;
                broker.SetIpcStatus(isConnected);

                if (isConnected) {
                    bus.Publish({ EventType::UI_STATUS_UPDATE, std::make_pair(UiStatusType::SUCCESS, std::string(PCrypt("Active").c_str())) });
                    std::string startupIp = ctx.GetTargetServer();
                    if (!startupIp.empty()) {
                        std::string connectCmd = std::string(PCrypt("connect ").c_str()) + startupIp + PCrypt("\n").c_str();
                        broker.PushToIPC(PacketBuilder::CreateString(CH_CMD_CONNECT_SERVER, connectCmd));
                    }
                }
                else {
                    if (ctx.isInjected) {
                        bus.Publish({ EventType::UI_STATUS_UPDATE, std::make_pair(UiStatusType::ERROR_STATE, std::string(PCrypt("Game Disconnected.").c_str())) });
                    }
                }
            }
        );
    }
}