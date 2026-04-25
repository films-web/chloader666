#pragma once
#include "protocol.hpp"
#include "message_broker.hpp"
#include "event_bus.hpp"
#include "session_context.hpp"
#include "json.hpp"
#include <string>

namespace IPCHandler {
    inline void ProcessMessage(const CH_Packet& pkt, MessageBroker& broker, EventBus& bus) {
        if (pkt.size < 0 || pkt.size > MAX_PAYLOAD_SIZE) return;

        if (pkt.type == CH_INFO_PLAYER_DATA) {
            if (pkt.size == sizeof(CH_PlayerDataPayload)) {
                const CH_PlayerDataPayload* data = reinterpret_cast<const CH_PlayerDataPayload*>(pkt.payload);
                nlohmann::json j;
                j["action"] = "update_state";
                j["data"]["name"] = data->name;
                j["data"]["playerNum"] = data->playerNum;
                j["data"]["state"] = data->inGame;
                j["data"]["server"] = data->server;
                broker.PushToWS(j.dump());
            }
        }

        else if (pkt.type == CH_CMD_REQUEST_PLAYER_LIST) {
            broker.PushToWS(nlohmann::json({ {"action", "get_player_list"} }).dump());
        }
        else if (pkt.type == CH_CMD_REQUEST_FAIRSHOT && pkt.size > 0) {
            std::string targetInfo(reinterpret_cast<const char*>(pkt.payload), pkt.size);
            broker.PushToWS(nlohmann::json({ {"action", "request_fairshot"}, {"target", targetInfo} }).dump());
        }
        else if (pkt.type == CH_CMD_REQUEST_GUID) {
            broker.PushToWS(nlohmann::json({ {"action", "request_guid"} }).dump());
        }
        else if (pkt.type == CH_CMD_REQUEST_SCAN) {
            bus.Publish({ EventType::START_SCAN, std::monostate{} });
        }
    }
}