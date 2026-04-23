#pragma once
#include <string>
#include <vector>
#include "json.hpp"
#include "session_context.hpp"
#include "message_broker.hpp"
#include "packet_builder.hpp"

using json = nlohmann::json;

namespace ServerHandler {

    inline void ProcessMessage(const std::string& msg, SessionContext& ctx, MessageBroker& broker, NetworkClient& netClient) {
        try {
            json j = json::parse(msg);

            if (j.value("status", "") == "error") {
                ctx.SetUiStatus("Auth Failed: " + j.value("message", "Unknown error"));
                netClient.Stop();
                return;
            }

            std::string action = j.value("action", "");

            if (action == "auth_result" && j.value("status", "") == "success") {
                ctx.SetServerGuid(j["data"].value("guid", ""));
                ctx.isAuthenticated = true;

                broker.PushToWS(json({ {"action", "pk3_whitelist"} }).dump());
                broker.PushToWS(json({ {"action", "payload"} }).dump());
            }
            else if (action == "whitelist_data") {
                std::vector<std::string> hashes;
                for (const auto& hash : j["data"]["hashes"]) {
                    hashes.push_back(hash.get<std::string>());
                }
                ctx.SetWhitelist(hashes);
                ctx.hasReceivedWhitelist = true;
            }
            else if (action == "payload_info") {
                ctx.SetDllInfo(
                    j["data"].value("url", ""),
                    j["data"].value("hash", ""),
                    j["data"].value("fileName", "cheatharam.dll")
                );
                ctx.hasReceivedDllInfo = true;
            }
            else if (action == "set_guid") {
                std::string guid = "";
                if (j.contains("data") && j["data"].contains("guid")) {
                    guid = j["data"].value("guid", "");
                }

                if (!guid.empty()) {
                    broker.PushToIPC(PacketBuilder::CreateString(CH_CMD_SET_GUID, guid));

                    broker.PushToIPC(PacketBuilder::CreateEmpty(CH_CMD_REQUEST_STATE));
                }
                else {
                    ctx.SetUiStatus("Error: Received empty GUID from server.");
                }
            }
            else if (action == "crash_client") {
                broker.PushToIPC(PacketBuilder::CreateEmpty(CH_CMD_CRASH_CLIENT));
            }
            else if (action == "player_list_result") {
                std::string formattedList = "";

                if (j.contains("data") && j["data"].contains("players") && j["data"]["players"].is_array()) {
                    for (const auto& p : j["data"]["players"]) {
                        int id = p.value("id", 0);
                        std::string guid = p.value("guid", "");
                        std::string name = p.value("name", "Unknown");

                        std::string shortGuid = guid.length() > 8 ? guid.substr(0, 8) : guid;

                        char line[128] = { 0 };
                        snprintf(line, sizeof(line), "^7%-4d %-16s %-16s\n", id, shortGuid.c_str(), name.c_str());
                        formattedList += line;
                    }
                }

                if (formattedList.empty()) {
                    formattedList = "^7No other AC players found.\n";
                }

                broker.PushToIPC(PacketBuilder::CreateString(CH_CMD_SET_PLAYER_LIST, formattedList));
            }
            else if (action == "fairshot_ack") {
                broker.PushToIPC(PacketBuilder::CreateEmpty(CH_CMD_FAIRSHOT_ACK));
            }
        }
        catch (const std::exception& e) {
            ctx.SetUiStatus(std::string("Server Handler Error: ") + e.what());
        }
    }
}