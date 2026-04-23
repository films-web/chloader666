#pragma once
#include <string>
#include "json.hpp"
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
    inline void Register(SessionContext& ctx, NetworkClient& netClient, IPCServer& ipcServer, MessageBroker& broker,
        const std::string& hwid, const std::string& signature, const std::string& gameRootFolder) {
        netClient.Start(std::string(Constants::WsUrl().c_str()),
            [&ctx, &broker, hwid, signature](bool isConnected, const std::string& errorMsg) {
                broker.SetNetworkStatus(isConnected);
                if (isConnected) {
                    ctx.SetUiStatus(PCrypt("Authenticating...").c_str());

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
                    ctx.SetUiStatus(errorMsg.empty() ? PCrypt("Disconnected.").c_str() : PCrypt("Net Error: ").c_str() + errorMsg);
                    ctx.SetServerGuid("-");
                    ctx.isAuthenticated = false;
                }
            },
            [&ctx, &netClient, &broker](const std::string& msg) {
                ServerHandler::ProcessMessage(msg, ctx, broker, netClient);
            }
        );

        ipcServer.Start(std::string(Constants::IpcPipeName().c_str()), [&broker, &ctx, gameRootFolder](const CH_Packet& pkt) {
            IPCHandler::ProcessMessage(pkt, broker, ctx, gameRootFolder);
            });
    }
}