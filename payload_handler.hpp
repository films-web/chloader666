#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <vector>
#include <fstream>
#include "poly_crypt.hpp"

class PayloadHandler {
public:
    struct ProtectedFile {
        HANDLE hFile = INVALID_HANDLE_VALUE;
        std::string path;

        __forceinline bool isValid() const { return hFile != INVALID_HANDLE_VALUE; }

        __forceinline ~ProtectedFile() {
            if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
            if (!path.empty()) DeleteFileA(path.c_str());
        }
    };

    static __forceinline bool CommitToDisk(const std::string& path, const std::vector<uint8_t>& data, ProtectedFile& outLock) {
        std::ofstream outFile(path, std::ios::binary);
        if (!outFile.is_open()) return false;

        outFile.write(reinterpret_cast<const char*>(data.data()), data.size());
        outFile.close();

        outLock.path = path;
        outLock.hFile = CreateFileA(path.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

        return outLock.isValid();
    }
};