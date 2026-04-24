#pragma once
#include <string>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <ctime>

namespace TimeUtils {
    inline std::string GetFormattedTime() {
        auto now = std::chrono::system_clock::now();
        std::time_t now_c = std::chrono::system_clock::to_time_t(now);
        std::tm parts;
        localtime_s(&parts, &now_c);
        std::stringstream timeStream;
        timeStream << std::put_time(&parts, "%I:%M:%S %p");

        return timeStream.str();
    }
}