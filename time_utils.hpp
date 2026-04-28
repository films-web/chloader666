#pragma once
#include <string>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <ctime>

namespace TimeUtils {
    static __forceinline std::string GetFormattedTime() {
        auto now = std::chrono::system_clock::now();
        std::time_t now_c = std::chrono::system_clock::to_time_t(now);
        std::tm parts;

        localtime_s(&parts, &now_c);

        std::stringstream timeStream;
        timeStream << std::put_time(&parts, "%I:%M:%S %p");

        return timeStream.str();
    }

    static __forceinline uint64_t GetUnixTimestamp() {
        return static_cast<uint64_t>(std::time(nullptr));
    }
}