#pragma once
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <cstdlib>

#include "session_context.hpp"

namespace ConsoleUI {

    inline void Run(SessionContext& ctx) {
        std::string lastStatus = "";

        while (ctx.isRunning) {
            std::string currentStatus = ctx.GetUiStatus();

            if (currentStatus != lastStatus) {
                system("cls");

                std::cout << "====================================\n";
                std::cout << "        CheatHaram Loader           \n";
                std::cout << "====================================\n";
                std::cout << " Server GUID: " << ctx.GetServerGuid() << "\n";
                std::cout << " Status:      " << currentStatus << "\n";
                std::cout << "====================================\n";

                lastStatus = currentStatus;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
}