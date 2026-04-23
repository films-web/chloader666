#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <thread>
#include <functional>
#include <atomic>
#include "protocol.hpp"

class IPCServer {
public:
    using PacketCallback = std::function<void(const CH_Packet&)>;

    IPCServer() : hPipe(INVALID_HANDLE_VALUE), isRunning(false) {}
    ~IPCServer() { Stop(); }

    void Start(const std::string& pipeName, PacketCallback onPacketReceived) {
        isRunning = true;

        ipcThread = std::thread([this, pipeName, onPacketReceived]() {
            while (isRunning) {
                hPipe = CreateNamedPipeA(pipeName.c_str(),
                    PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                    1, sizeof(CH_Packet), sizeof(CH_Packet), 0, NULL);

                if (hPipe != INVALID_HANDLE_VALUE) {

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
                            while (isRunning) {
                                CH_Packet inPkt = { 0 };
                                DWORD bytesRead = 0;

                                OVERLAPPED readOv = { 0 };
                                readOv.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

                                if (!readOv.hEvent) {
                                    break;
                                }

                                bool readOk = false;

                                // FIXED: Read the entire max-size packet in one fell swoop
                                if (ReadFile(hPipe, &inPkt, sizeof(CH_Packet), NULL, &readOv) == FALSE) {
                                    DWORD err = GetLastError();

                                    if (err == ERROR_IO_PENDING) {
                                        if (WaitForSingleObject(readOv.hEvent, 2000) == WAIT_OBJECT_0) {
                                            if (GetOverlappedResult(hPipe, &readOv, &bytesRead, FALSE)) readOk = true;
                                        }
                                        else {
                                            CancelIo(hPipe);
                                        }
                                    }
                                    else if (err == ERROR_MORE_DATA) {
                                        // Handle case where packet is somehow larger than struct
                                        if (GetOverlappedResult(hPipe, &readOv, &bytesRead, FALSE)) readOk = true;
                                    }
                                }
                                else {
                                    if (GetOverlappedResult(hPipe, &readOv, &bytesRead, FALSE)) readOk = true;
                                }
                                CloseHandle(readOv.hEvent);

                                // FIXED: If we read successfully, process the single buffer
                                if (readOk && bytesRead >= (sizeof(int) * 3)) {

                                    if (inPkt.magic != CH_MAGIC_WORD) {
                                        break; // Invalid magic, disconnect
                                    }

                                    // Safely validate the stated size
                                    if (inPkt.size >= 0 && inPkt.size <= MAX_PAYLOAD_SIZE) {
                                        onPacketReceived(inPkt);
                                    }
                                    else {
                                        break; // Malformed packet size, disconnect
                                    }
                                }
                                else {
                                    break; // Read failed or client disconnected
                                }
                            }
                        }
                        CloseHandle(connectOv.hEvent);
                    }

                    DisconnectNamedPipe(hPipe);
                    CloseHandle(hPipe);
                    hPipe = INVALID_HANDLE_VALUE;
                }

                if (isRunning) std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            });
    }

    void SendPacket(const CH_Packet& pkt) {
        if (hPipe != INVALID_HANDLE_VALUE) {
            OVERLAPPED writeOv = { 0 };
            writeOv.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

            if (!writeOv.hEvent) return;

            DWORD bytesWritten = 0;
            DWORD toWrite = (sizeof(int) * 3) + pkt.size;

            if (WriteFile(hPipe, &pkt, toWrite, NULL, &writeOv) == FALSE) {
                if (GetLastError() == ERROR_IO_PENDING) {
                    if (WaitForSingleObject(writeOv.hEvent, 2000) == WAIT_OBJECT_0) {
                        GetOverlappedResult(hPipe, &writeOv, &bytesWritten, FALSE);
                    }
                    else {
                        CancelIo(hPipe);
                    }
                }
            }
            CloseHandle(writeOv.hEvent);
        }
    }

    void Stop() {
        isRunning = false;

        if (hPipe != INVALID_HANDLE_VALUE) {
            CancelIoEx(hPipe, NULL);
        }

        if (ipcThread.joinable()) {
            ipcThread.join();
        }

        if (hPipe != INVALID_HANDLE_VALUE) {
            CloseHandle(hPipe);
            hPipe = INVALID_HANDLE_VALUE;
        }
    }

private:
    HANDLE hPipe;
    std::atomic<bool> isRunning;
    std::thread ipcThread;
};