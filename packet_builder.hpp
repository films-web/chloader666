#pragma once
#include "protocol.hpp"
#include <string>

namespace PacketBuilder {

    static __forceinline CH_Packet CreateEmpty(int type) {
        CH_Packet pkt = { 0 };
        pkt.magic = CH_MAGIC_WORD;
        pkt.type = type;
        pkt.size = 0;
        return pkt;
    }

    static __forceinline CH_Packet CreateString(int type, const std::string& data) {
        CH_Packet pkt = { 0 };
        pkt.magic = CH_MAGIC_WORD;
        pkt.type = type;
        pkt.size = static_cast<int>(data.length() > MAX_PAYLOAD_SIZE ? MAX_PAYLOAD_SIZE : data.length());

        if (pkt.size > 0) {
            memcpy(pkt.payload, data.c_str(), pkt.size);
        }

        return pkt;
    }
}