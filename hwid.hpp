#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>

#include "crypto.hpp"

class HWIDManager {
public:
    static std::string Generate() {
        std::stringstream ss;
        ss << GetCPUId()
            << GetWindowsProductId()
            << GetMotherboardSerial();

        return Crypto::CalculateSHA256String(ss.str());
    }

private:
    static std::string GetCPUId() {
        int info[4] = { 0 };
        __cpuid(info, 1);
        std::stringstream ss;
        ss << std::hex << std::setfill('0')
            << std::setw(8) << info[0]
            << std::setw(8) << info[3];
        return ss.str();
    }

    static std::string GetWindowsProductId() {
        char value[256] = { 0 };
        DWORD size = sizeof(value);
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegQueryValueExA(hKey, "ProductId", nullptr, nullptr,
                reinterpret_cast<LPBYTE>(value), &size);
            RegCloseKey(hKey);
            return std::string(value);
        }
        return "NOPID";
    }

    static std::string GetMotherboardSerial() {
        DWORD size = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
        if (size == 0) return "NOMB";

        std::vector<BYTE> buf(size);
        if (GetSystemFirmwareTable('RSMB', 0, buf.data(), size) == 0)
            return "NOMB";

        BYTE* p = buf.data() + 8;
        BYTE* end = buf.data() + size;

        while (p < end) {
            BYTE type = p[0];
            BYTE length = p[1];
            if (length < 4 || p + length > end) break;

            if (type == 2) {
                BYTE serialIdx = (length > 7) ? p[7] : 0;
                if (serialIdx > 0) {
                    const char* str = reinterpret_cast<const char*>(p + length);
                    for (BYTE i = 1; i < serialIdx && str < reinterpret_cast<const char*>(end); ++i)
                        str += strlen(str) + 1;
                    if (str < reinterpret_cast<const char*>(end) && strlen(str) > 0)
                        return std::string(str);
                }
                return "NOMB";
            }

            p += length;
            while (p + 1 < end && !(p[0] == 0 && p[1] == 0)) ++p;
            p += 2;
        }

        return "NOMB";
    }
};