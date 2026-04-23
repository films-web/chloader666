#pragma once
#include "protocol.hpp"
#include "message_broker.hpp"
#include "session_context.hpp"
#include "integrity_scanner.hpp"
#include "packet_builder.hpp"
#include "json.hpp"
#include <string>
#include <algorithm>

namespace IPCHandler {

    inline void ProcessMessage(const CH_Packet& pkt, MessageBroker& broker, SessionContext& ctx, const std::string& gameRootFolder) {

        if (pkt.size < 0 || pkt.size > MAX_PAYLOAD_SIZE) {
            return;
        }

        if (pkt.type == CH_INFO_PLAYER_DATA) {
            if (pkt.size > 0) {
                std::string data(reinterpret_cast<const char*>(pkt.payload), pkt.size);
                broker.PushToWS(data);
            }
        }
        else if (pkt.type == CH_CMD_REQUEST_PLAYER_LIST) {
            nlohmann::json request = { {"action", "get_player_list"} };
            broker.PushToWS(request.dump());
        }
        else if (pkt.type == CH_CMD_REQUEST_FAIRSHOT) {
            if (pkt.size > 0) {
                std::string targetInfo(reinterpret_cast<const char*>(pkt.payload), pkt.size);
                nlohmann::json request = {
                    {"action", "request_fairshot"},
                    {"target", targetInfo}
                };
                broker.PushToWS(request.dump());
            }
        }
        else if (pkt.type == CH_CMD_REQUEST_GUID) {
            nlohmann::json request = { {"action", "request_guid"} };
            broker.PushToWS(request.dump());
        }
        else if (pkt.type == CH_CMD_REQUEST_SCAN) {
            std::string detectionResult = IntegrityScanner::VerifyGameFolder(gameRootFolder, ctx.GetWhitelist());

            if (!detectionResult.empty()) {
                broker.PushToIPC(PacketBuilder::CreateEmpty(CH_CMD_CRASH_CLIENT));
            }
        }
    }
}