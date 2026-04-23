#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <functional>

class HWIDManager {
public:
    static std::string Generate() {
        std::stringstream ss;
        ss << GetCPUId() << "-" << GetDriveSerial() << "-" << GetMachineName();
        return ss.str();
    }

private:
    static DWORD GetDriveSerial() {
        DWORD serialNum = 0;
        GetVolumeInformationA("C:\\", nullptr, 0, &serialNum, nullptr, nullptr, nullptr, 0);
        return serialNum;
    }

    static std::string GetCPUId() {
        int cpuInfo[4] = { 0 };
        __cpuid(cpuInfo, 0);
        std::stringstream ss;
        ss << std::hex << std::setfill('0') << std::setw(8) << cpuInfo[0] << std::setw(8) << cpuInfo[1];
        return ss.str();
    }

    static std::string GetMachineName() {
        char compName[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD size = sizeof(compName);
        if (GetComputerNameA(compName, &size)) return std::string(compName);
        return "UNKNOWN";
    }
};