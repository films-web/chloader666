#pragma once
#include <string>
#include <vector>
#include "json.hpp"
#include "event_bus.hpp"
#include "session_context.hpp"
#include "message_broker.hpp"
#include "packet_builder.hpp"

using json = nlohmann::json;

namespace ServerHandler {
    inline void ProcessMessage(const std::string& msg, EventBus& bus, SessionContext& ctx, MessageBroker& broker) {
        try {
            json j = json::parse(msg);

            if (j.value("status", "") == "error") {
                bus.Publish({ EventType::UI_STATUS_UPDATE, "Auth Failed: " + j.value("message", "Unknown error") });
                return;
            }

            std::string action = j.value("action", "");

            if (action == "auth_result" && j.value("status", "") == "success") {
                std::string guid = j["data"].value("guid", "");
                ctx.SetServerGuid(guid);
                ctx.isAuthenticated = true;

                broker.PushToWS(json({ {"action", "pk3_whitelist"} }).dump());
                broker.PushToWS(json({ {"action", "payload"} }).dump());

                bus.Publish({ EventType::AUTH_SUCCESS, guid });
            }
            else if (action == "whitelist_data") {
                std::vector<std::string> hashes;
                for (const auto& hash : j["data"]["hashes"]) {
                    hashes.push_back(hash.get<std::string>());
                }
                ctx.SetWhitelist(hashes);
                bus.Publish({ EventType::WHITELIST_RECEIVED, hashes });
            }
            else if (action == "payload_info") {
                ctx.SetDllInfo(
                    j["data"].value("url", ""),
                    j["data"].value("hash", ""),
                    j["data"].value("fileName", "cheatharam.dll")
                );
                bus.Publish({ EventType::PAYLOAD_INFO_RECEIVED, std::monostate{} });
            }
            else if (action == "set_guid") {
                std::string guid = j.contains("data") ? j["data"].value("guid", "") : "";
                if (!guid.empty()) {
                    broker.PushToIPC(PacketBuilder::CreateString(CH_CMD_SET_GUID, guid));
                    broker.PushToIPC(PacketBuilder::CreateEmpty(CH_CMD_REQUEST_STATE));
                }
            }
            else if (action == "crash_client") {
                bus.Publish({ EventType::CRASH_REQUESTED, std::monostate{} });
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
                if (formattedList.empty()) formattedList = "^7No other AC players found.\n";
                broker.PushToIPC(PacketBuilder::CreateString(CH_CMD_SET_PLAYER_LIST, formattedList));
            }
            else if (action == "fairshot_ack") {
                broker.PushToIPC(PacketBuilder::CreateEmpty(CH_CMD_FAIRSHOT_ACK));
            }
        }
        catch (const std::exception& e) {
            bus.Publish({ EventType::UI_STATUS_UPDATE, std::string("Server Error: ") + e.what() });
        }
    }
}