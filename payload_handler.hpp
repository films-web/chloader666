#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <vector>
#include <fstream>
#include "poly_crypt.hpp"

class PayloadHandler {
public:
    struct Session {
        HANDLE hFile = INVALID_HANDLE_VALUE;
        std::string path;

        __forceinline bool IsValid() const { return hFile != INVALID_HANDLE_VALUE; }

        __forceinline ~Session() {
            if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
            if (!path.empty()) DeleteFileA(path.c_str());
        }
    };

    static __forceinline bool CommitToDisk(const std::string& path, const std::vector<uint8_t>& data, Session& outSession) {
        std::ofstream outFile(path, std::ios::binary);
        if (!outFile.is_open()) return false;

        outFile.write(reinterpret_cast<const char*>(data.data()), data.size());
        outFile.close();
        outSession.path = path;
        outSession.hFile = CreateFileA(path.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

        return outSession.IsValid();
    }
};