#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iostream>
#include <string>
#include <cstdlib>
#include "event_bus.hpp"
#include "session_context.hpp"

namespace ConsoleUI {
    inline void Initialize() {
        HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
        DWORD prev_mode;
        GetConsoleMode(hInput, &prev_mode);
        SetConsoleMode(hInput, ENABLE_EXTENDED_FLAGS | (prev_mode & ~ENABLE_QUICK_EDIT_MODE));
        HANDLE hOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_CURSOR_INFO cursorInfo;
        GetConsoleCursorInfo(hOutput, &cursorInfo);
        cursorInfo.bVisible = false;
        SetConsoleCursorInfo(hOutput, &cursorInfo);
        SetConsoleTitleA(PCrypt("CheatHaram").c_str());
    }

    inline void Register(EventBus& bus, SessionContext& ctx) {
        bus.Subscribe(EventType::UI_STATUS_UPDATE, [&ctx](const Event& e) {

            auto statusData = std::get<std::pair<UiStatusType, std::string>>(e.payload);
            ctx.SetUiStatus(statusData.first, statusData.second);

            system("cls");
            HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

            std::cout << "====================================\n";
            std::cout << "        CheatHaram Loader           \n";
            std::cout << "====================================\n";
            std::cout << " Server GUID: " << ctx.GetServerGuid() << "\n";
            std::cout << " Status:      ";

            switch (statusData.first) {
            case UiStatusType::LOADING:
                SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                break;
            case UiStatusType::SUCCESS:
                SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                break;
            case UiStatusType::ACTIVE:
                SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
                break;
            case UiStatusType::ERROR_STATE:
                SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
                break;
            default:
                SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                break;
            }

            std::cout << statusData.second << "\n";

            SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            std::cout << "====================================\n";
            });
    }
}