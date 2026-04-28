#pragma once
#include <string>
#include <vector>
#include <utility>

#include "messages.pb.h"
#include "secure_protocol.hpp"
#include "event_bus.hpp"
#include "session_context.hpp"
#include "message_broker.hpp"
#include "packet_builder.hpp"
#include "time_utils.hpp"
#include "poly_crypt.hpp"

namespace ServerHandler {
    static __forceinline void ProcessMessage(const std::string& rawMsg, EventBus& bus, SessionContext& ctx, MessageBroker& broker) {
        try {
            CheatHaram::S2C_Message msg;

            if (!SecureProtocol::Unpack(rawMsg, msg)) return;

            if (!msg.success()) {
                // STEALTH: Encrypt fallback error strings
                std::string errorText = msg.message().empty() ? PCrypt("Unknown server error").c_str() : msg.message();
                bus.Publish({ EventType::UI_STATUS_UPDATE, std::make_pair(UiStatusType::ERROR_STATE, std::string(PCrypt("Auth Failed: ").c_str()) + errorText) });
                return;
            }

            switch (msg.action()) {
            case CheatHaram::ActionType::AUTH_RESULT: {
                std::string guid = msg.guid();
                ctx.SetServerGuid(guid);
                ctx.isAuthenticated = true;

                CheatHaram::C2S_Message wlReq;
                wlReq.set_action(CheatHaram::ActionType::PK3_WHITELIST_REQ);
                broker.PushToWS(wlReq);

                CheatHaram::C2S_Message plReq;
                plReq.set_action(CheatHaram::ActionType::PAYLOAD_REQ);
                broker.PushToWS(plReq);

                bus.Publish({ EventType::AUTH_SUCCESS, guid });
                break;
            }

            case CheatHaram::ActionType::PK3_WHITELIST_RESULT: {
                std::vector<std::string> hashes;
                for (int i = 0; i < msg.hashes_size(); ++i) {
                    hashes.push_back(msg.hashes(i));
                }
                ctx.SetWhitelist(hashes);
                bus.Publish({ EventType::WHITELIST_RECEIVED, hashes });
                break;
            }

            case CheatHaram::ActionType::PAYLOAD_RESULT: {
                // STEALTH: Encrypt default filename
                std::string fileName = msg.payload_name().empty() ? PCrypt("cheatharam.dll").c_str() : msg.payload_name();
                ctx.SetDllInfo(msg.payload_url(), msg.payload_hash(), fileName);
                bus.Publish({ EventType::PAYLOAD_INFO_RECEIVED, std::monostate{} });
                break;
            }

            case CheatHaram::ActionType::SET_GUID: {
                std::string guid = msg.guid();
                if (!guid.empty()) {
                    std::string timeStr = TimeUtils::GetFormattedTime();
                    // STEALTH: Encrypt the chat notification strings
                    std::string sayCmd = std::string(PCrypt("say ^3CheatHaram: ^6Guid: ^7").c_str()) + guid + PCrypt(" ^1").c_str() + timeStr + PCrypt("\n").c_str();
                    broker.PushToIPC(PacketBuilder::CreateString(CH_CMD_SET_GUID, sayCmd));
                    broker.PushToIPC(PacketBuilder::CreateEmpty(CH_CMD_REQUEST_STATE));
                }
                break;
            }

            case CheatHaram::ActionType::CRASH_CLIENT: {
                bus.Publish({ EventType::CRASH_REQUESTED, std::monostate{} });
                break;
            }

            case CheatHaram::ActionType::PLAYER_LIST_RESULT: {
                std::string formattedList = "";
                for (int i = 0; i < msg.players_list_size(); ++i) {
                    const auto& p = msg.players_list(i);
                    std::string shortGuid = p.guid().length() > 8 ? p.guid().substr(0, 8) : p.guid();

                    char line[128] = { 0 };
                    snprintf(line, sizeof(line), PCrypt("^7%-4d %-16s %-16s\n").c_str(), p.id(), shortGuid.c_str(), p.name().c_str());
                    formattedList += line;
                }

                if (formattedList.empty()) formattedList = "";
                broker.PushToIPC(PacketBuilder::CreateString(CH_CMD_SET_PLAYER_LIST, formattedList));
                break;
            }

            case CheatHaram::ActionType::REQUEST_FAIRSHOT: {
                broker.PushToIPC(PacketBuilder::CreateEmpty(CH_CMD_FAIRSHOT_ACK));
                break;
            }

            default:
                break;
            }
        }
        catch (const std::exception& e) {
            bus.Publish({ EventType::UI_STATUS_UPDATE, std::make_pair(UiStatusType::ERROR_STATE, std::string(PCrypt("Protocol Error: ").c_str()) + e.what()) });
        }
    }
}