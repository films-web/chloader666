#pragma once
#include "protocol.hpp"
#include "message_broker.hpp"
#include "event_bus.hpp"
#include "session_context.hpp"
#include "messages.pb.h"
#include <string>

namespace IPCHandler {
    inline void ProcessMessage(const CH_Packet& pkt, MessageBroker& broker, EventBus& bus) {
        if (pkt.size < 0 || pkt.size > MAX_PAYLOAD_SIZE) return;

        if (pkt.type == CH_INFO_PLAYER_DATA) {
            if (pkt.size >= sizeof(CH_PlayerDataPayload)) {
                const CH_PlayerDataPayload* data = reinterpret_cast<const CH_PlayerDataPayload*>(pkt.payload);

                CheatHaram::C2S_Message msg;
                msg.set_action(CheatHaram::ActionType::UPDATE_PLAYER_STATE);
                auto* pData = msg.mutable_player_data();
                pData->set_id(data->playerNum);
                pData->set_name(data->name);
                pData->set_server_ip(data->server);
                pData->set_in_game(data->inGame > 0);

                broker.PushToWS(msg);
            }
        }

        else if (pkt.type == CH_CMD_REQUEST_PLAYER_LIST) {
            CheatHaram::C2S_Message msg;
            msg.set_action(CheatHaram::ActionType::PLAYER_LIST_REQ);
            broker.PushToWS(msg);
        }

        else if (pkt.type == CH_CMD_REQUEST_FAIRSHOT && pkt.size > 0) {
            CheatHaram::C2S_Message msg;
            msg.set_action(CheatHaram::ActionType::REQUEST_FAIRSHOT);
            std::string targetInfo(reinterpret_cast<const char*>(pkt.payload), pkt.size);
            msg.set_target(targetInfo);

            broker.PushToWS(msg);
        }

        else if (pkt.type == CH_CMD_REQUEST_GUID) {
            CheatHaram::C2S_Message msg;
            msg.set_action(CheatHaram::ActionType::GET_GUID_REQ);
            broker.PushToWS(msg);
        }

        else if (pkt.type == CH_CMD_REQUEST_SCAN) {
            bus.Publish({ EventType::START_SCAN, std::monostate{} });
        }
    }
}