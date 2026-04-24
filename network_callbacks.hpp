#pragma once
#include <string>
#include <utility>
#include "json.hpp"
#include "event_bus.hpp"
#include "session_context.hpp"
#include "network_client.hpp"
#include "message_broker.hpp"
#include "ipc_server.hpp"
#include "server_handler.hpp"
#include "ipc_handler.hpp"
#include "constants.hpp"
#include "poly_crypt.hpp"

using json = nlohmann::json;

namespace NetworkCallbacks {
    inline void Register(EventBus& bus, SessionContext& ctx, NetworkClient& netClient, IPCServer& ipcServer, MessageBroker& broker,
        const std::string& hwid, const std::string& signature) {

        netClient.Start(std::string(Constants::WsUrl().c_str()),
            [&bus, &broker, hwid, signature](bool isConnected, const std::string& errorMsg) {
                broker.SetNetworkStatus(isConnected);
                if (isConnected) {
                    bus.Publish({ EventType::UI_STATUS_UPDATE, std::make_pair(UiStatusType::LOADING, std::string(PCrypt("Authenticating...").c_str())) });

                    json authPayload = {
                        {"action", "auth"},
                        {"data", {
                            {"hwid", hwid},
                            {"signature", signature},
                            {"currentName", "UnnamedPlayer"}
                        }}
                    };
                    broker.PushToWS(authPayload.dump());
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

        ipcServer.Start(std::string(Constants::IpcPipeName().c_str()), [&broker, &bus](const CH_Packet& pkt) {
            IPCHandler::ProcessMessage(pkt, broker, bus);
            });
    }
}