#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <thread>
#include <chrono>
#include <atomic>
#include "constants.hpp"
#include "event_bus.hpp"
#include "poly_crypt.hpp"

namespace UrlLauncher {
    static inline HANDLE hMutex = NULL;
    static __forceinline void RegisterProtocol() {
        char exePath[MAX_PATH];
        GetModuleFileNameA(NULL, exePath, MAX_PATH);

        HKEY hKey;
        std::string keyPath = PCrypt("Software\\Classes\\cheatharam").c_str();

        if (RegCreateKeyExA(HKEY_CURRENT_USER, keyPath.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            std::string desc = PCrypt("URL:CheatHaram Protocol").c_str();
            RegSetValueExA(hKey, NULL, 0, REG_SZ, (const BYTE*)desc.c_str(), (DWORD)desc.length() + 1);

            std::string urlProtocol = PCrypt("URL Protocol").c_str();
            RegSetValueExA(hKey, urlProtocol.c_str(), 0, REG_SZ, (const BYTE*)"", 1);
            RegCloseKey(hKey);
        }

        std::string cmdKeyPath = keyPath + PCrypt("\\shell\\open\\command").c_str();
        if (RegCreateKeyExA(HKEY_CURRENT_USER, cmdKeyPath.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            std::string cmd = std::string(PCrypt("\"").c_str()) + exePath + PCrypt("\" \"%1\"").c_str();
            RegSetValueExA(hKey, NULL, 0, REG_SZ, (const BYTE*)cmd.c_str(), (DWORD)cmd.length() + 1);
            RegCloseKey(hKey);
        }
    }

    static __forceinline std::string ParseArgument(int argc, char* argv[]) {
        if (argc > 1) {
            std::string inputArg(argv[1]);
            std::string scheme = PCrypt("cheatharam://").c_str();
            if (inputArg.find(scheme) == 0) {
                std::string serverAddress = inputArg.substr(scheme.length());
                if (!serverAddress.empty() && serverAddress.back() == '/') serverAddress.pop_back();
                return serverAddress;
            }
            return inputArg;
        }
        return "";
    }

    static __forceinline bool ForwardIfAlreadyRunning(const std::string& serverAddress) {
        hMutex = CreateMutexA(NULL, TRUE, PCrypt("Global\\CH_Instance_Guard").c_str());

        if (GetLastError() == ERROR_ALREADY_EXISTS) {
            std::string pipeName = PCrypt("\\\\.\\pipe\\CHUrlPipe").c_str();

            if (WaitNamedPipeA(pipeName.c_str(), 2000)) {
                HANDLE hPipe = CreateFileA(pipeName.c_str(), GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
                if (hPipe != INVALID_HANDLE_VALUE) {
                    std::string msg = serverAddress.empty() ? PCrypt("WAKE_UP").c_str() : std::string(PCrypt("CONNECT_IP:").c_str()) + serverAddress;
                    DWORD bytesWritten;
                    WriteFile(hPipe, msg.c_str(), (DWORD)msg.length(), &bytesWritten, NULL);
                    CloseHandle(hPipe);
                }
            }
            return true;
        }
        return false;
    }

    static __forceinline std::thread StartPrimaryListener(EventBus& bus, std::atomic<bool>& isRunning) {
        return std::thread([&bus, &isRunning]() {
            std::string pipeName = PCrypt("\\\\.\\pipe\\CHUrlPipe").c_str();

            HANDLE hPipe = CreateNamedPipeA(pipeName.c_str(),
                PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                1, 1024, 1024, 0, NULL);

            if (hPipe == INVALID_HANDLE_VALUE) return;

            while (isRunning) {
                OVERLAPPED connectOv = { 0 };
                connectOv.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

                if (connectOv.hEvent) {
                    bool connected = ConnectNamedPipe(hPipe, &connectOv) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

                    if (!connected && GetLastError() == ERROR_IO_PENDING) {
                        while (isRunning) {
                            if (WaitForSingleObject(connectOv.hEvent, 100) == WAIT_OBJECT_0) {
                                connected = true;
                                break;
                            }
                        }
                    }

                    if (connected && isRunning) {
                        char buffer[1024];
                        DWORD bytesRead;
                        OVERLAPPED readOv = { 0 };
                        readOv.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

                        if (readOv.hEvent) {
                            bool readOk = false;
                            if (ReadFile(hPipe, buffer, sizeof(buffer) - 1, NULL, &readOv) == FALSE) {
                                if (GetLastError() == ERROR_IO_PENDING) {
                                    while (isRunning) {
                                        if (WaitForSingleObject(readOv.hEvent, 100) == WAIT_OBJECT_0) {
                                            if (GetOverlappedResult(hPipe, &readOv, &bytesRead, FALSE)) readOk = true;
                                            break;
                                        }
                                    }
                                }
                            }
                            else {
                                if (GetOverlappedResult(hPipe, &readOv, &bytesRead, FALSE)) readOk = true;
                            }

                            if (readOk && bytesRead > 0) {
                                buffer[bytesRead] = '\0';
                                std::string msg(buffer);

                                HWND hwnd = GetConsoleWindow();
                                if (hwnd) {
                                    ShowWindow(hwnd, SW_RESTORE);
                                    SetForegroundWindow(hwnd);
                                }

                                std::string connectCmd = PCrypt("CONNECT_IP:").c_str();
                                if (msg.rfind(connectCmd, 0) == 0) {
                                    std::string targetIp = msg.substr(connectCmd.length());
                                    bus.Publish({ EventType::URL_CONNECT_REQUESTED, targetIp });
                                }
                            }
                            CloseHandle(readOv.hEvent);
                        }
                    }
                    CloseHandle(connectOv.hEvent);
                }
                DisconnectNamedPipe(hPipe);
                if (isRunning) std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
            CloseHandle(hPipe);
            });
    }
}