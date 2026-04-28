#pragma once
#define WIN32_LEAN_AND_MEAN
#include <string>
#include <ctime>
#include "json.hpp"
#include "aes_crypt.hpp"
#include "constants.hpp"

class SecureProtocol {
public:
    static std::string Pack(const std::string& rawJsonMsg) {
        try {
            nlohmann::json j = nlohmann::json::parse(rawJsonMsg);
            j["timestamp"] = std::time(nullptr);
            return AESCrypt::Encrypt(j.dump(), Constants::AesTransportKey().c_str());
        }
        catch (...) {
            return AESCrypt::Encrypt(rawJsonMsg, Constants::AesTransportKey().c_str());
        }
    }

    static std::string Unpack(const std::string& encryptedPayload) {
        return AESCrypt::Decrypt(encryptedPayload, Constants::AesTransportKey().c_str());
    }
};