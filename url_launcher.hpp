#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <thread>
#include <chrono>

#include "constants.hpp"
#include "session_context.hpp"
#include "message_broker.hpp"
#include "packet_builder.hpp"

class UrlLauncher {
public:
    static void RegisterProtocol() {
        char exePath[MAX_PATH];
        GetModuleFileNameA(NULL, exePath, MAX_PATH);

        HKEY hKey;
        std::string keyPath = "Software\\Classes\\cheatharam";

        if (RegCreateKeyExA(HKEY_CURRENT_USER, keyPath.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            std::string desc = "URL:CheatHaram Protocol";
            RegSetValueExA(hKey, NULL, 0, REG_SZ, (const BYTE*)desc.c_str(), desc.length() + 1);
            RegSetValueExA(hKey, "URL Protocol", 0, REG_SZ, (const BYTE*)"", 1);
            RegCloseKey(hKey);
        }

        std::string cmdKeyPath = keyPath + "\\shell\\open\\command";
        if (RegCreateKeyExA(HKEY_CURRENT_USER, cmdKeyPath.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            std::string cmd = "\"" + std::string(exePath) + "\" \"%1\"";
            RegSetValueExA(hKey, NULL, 0, REG_SZ, (const BYTE*)cmd.c_str(), cmd.length() + 1);
            RegCloseKey(hKey);
        }
    }

    static std::string ParseArgument(int argc, char* argv[]) {
        if (argc > 1) {
            std::string inputArg(argv[1]);
            std::string scheme = "cheatharam://";

            if (inputArg.find(scheme) == 0) {
                std::string serverAddress = inputArg.substr(scheme.length());
                if (!serverAddress.empty() && serverAddress.back() == '/') {
                    serverAddress.pop_back();
                }
                return serverAddress;
            }
        }
        return ""; // Return empty string if launched normally
    }

    static bool ForwardIfAlreadyRunning(const std::string& serverAddress) {
        if (WaitNamedPipeA("\\\\.\\pipe\\CHUrlPipe", 10)) {
            HANDLE hPipe = CreateFileA("\\\\.\\pipe\\CHUrlPipe", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
            if (hPipe != INVALID_HANDLE_VALUE) {
                std::string msg = serverAddress.empty() ? "WAKE_UP" : "CONNECT_IP:" + serverAddress;

                DWORD bytesWritten;
                WriteFile(hPipe, msg.c_str(), msg.length(), &bytesWritten, NULL);
                CloseHandle(hPipe);
            }
            return true; // Another instance is running, exit this one
        }
        return false;
    }

    // Returns a std::thread so we can join it cleanly instead of detaching
    static std::thread StartPrimaryListener(SessionContext& ctx, MessageBroker& broker) {
        return std::thread([&ctx, &broker]() {
            while (ctx.isRunning) {
                HANDLE hPipe = CreateNamedPipeA("\\\\.\\pipe\\CHUrlPipe",
                    PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED, // Added Overlapped IO
                    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                    1, 1024, 1024, 0, NULL);

                if (hPipe != INVALID_HANDLE_VALUE) {
                    OVERLAPPED connectOv = { 0 };
                    connectOv.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

                    if (connectOv.hEvent) {
                        bool connected = ConnectNamedPipe(hPipe, &connectOv) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

                        // Wait for connection cleanly, checking isRunning
                        if (!connected && GetLastError() == ERROR_IO_PENDING) {
                            while (ctx.isRunning) {
                                if (WaitForSingleObject(connectOv.hEvent, 100) == WAIT_OBJECT_0) {
                                    connected = true;
                                    break;
                                }
                            }
                        }

                        if (connected && ctx.isRunning) {
                            char buffer[1024];
                            DWORD bytesRead;
                            OVERLAPPED readOv = { 0 };
                            readOv.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

                            if (readOv.hEvent) {
                                bool readOk = false;
                                if (ReadFile(hPipe, buffer, sizeof(buffer) - 1, NULL, &readOv) == FALSE) {
                                    if (GetLastError() == ERROR_IO_PENDING) {
                                        while (ctx.isRunning) {
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

                                    if (msg == "WAKE_UP") {
                                        HWND hwnd = GetConsoleWindow();
                                        ShowWindow(hwnd, SW_RESTORE);
                                        SetForegroundWindow(hwnd);
                                    }
                                    else if (msg.rfind("CONNECT_IP:", 0) == 0) {
                                        std::string targetIp = msg.substr(11);

                                        // 1. Thread-safe save to context
                                        ctx.SetTargetServer(targetIp);

                                        // 2. Safely push binary packet to the DLL via the broker
                                        broker.PushToIPC(PacketBuilder::CreateString(CH_CMD_CONNECT_SERVER, targetIp));

                                        // 3. Restore window
                                        HWND hwnd = GetConsoleWindow();
                                        ShowWindow(hwnd, SW_RESTORE);
                                        SetForegroundWindow(hwnd);
                                    }
                                }
                                CloseHandle(readOv.hEvent);
                            }
                        }
                        CloseHandle(connectOv.hEvent);
                    }
                    DisconnectNamedPipe(hPipe);
                    CloseHandle(hPipe);
                }
                if (ctx.isRunning) std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            });
    }
};