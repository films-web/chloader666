#pragma once
#define WIN32_LEAN_AND_MEAN
#include <string>
#include <ctime>
#include "messages.pb.h"
#include "aes_crypt.hpp"
#include "constants.hpp"
#include "time_utils.hpp"

class SecureProtocol {
public:
    static __forceinline std::string Pack(CheatHaram::C2S_Message& msg) {
        msg.set_timestamp(TimeUtils::GetUnixTimestamp());
        std::string serializedData;
        if (!msg.SerializeToString(&serializedData)) return "";
        return AESCrypt::Encrypt(serializedData, Constants::AesTransportKey().c_str());
    }

    static __forceinline bool Unpack(const std::string& encryptedPayload, CheatHaram::S2C_Message& outMsg) {
        std::string decryptedData = AESCrypt::Decrypt(encryptedPayload, Constants::AesTransportKey().c_str());
        if (decryptedData.empty()) return false;
        return outMsg.ParseFromString(decryptedData);
    }
};