#pragma once
#include <iostream>
#include <string>
#include <cstdlib>
#include "event_bus.hpp"
#include "session_context.hpp"

namespace ConsoleUI {
    inline void Register(EventBus& bus, SessionContext& ctx) {
        bus.Subscribe(EventType::UI_STATUS_UPDATE, [&ctx](const Event& e) {
            std::string currentStatus = std::get<std::string>(e.payload);
            ctx.SetUiStatus(currentStatus);

            system("cls");
            std::cout << "====================================\n";
            std::cout << "        CheatHaram Loader           \n";
            std::cout << "====================================\n";
            std::cout << " Server GUID: " << ctx.GetServerGuid() << "\n";
            std::cout << " Status:      " << currentStatus << "\n";
            std::cout << "====================================\n";
            });
    }
}