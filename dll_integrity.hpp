#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <thread>
#include <atomic>
#include <chrono>

#include "poly_crypt.hpp"

class DllIntegrity {
private:
    static inline std::atomic<bool> isRunning{ false };
    static inline uint32_t baselineHash = 0;
    static inline DWORD targetPID = 0;
    static inline DWORD_PTR textBaseAddress = 0;
    static inline DWORD textSectionSize = 0;

    static __forceinline uint32_t HashBuffer(const BYTE* data, size_t size) {
        uint32_t hash = 0x811c9dc5;
        for (size_t i = 0; i < size; ++i) { hash ^= data[i]; hash *= 0x01000193; }
        return hash;
    }

    static __forceinline uint32_t CalculateRemoteHash() {
        if (textBaseAddress == 0 || textSectionSize == 0) return 0;
        HANDLE hProc = OpenProcess(PROCESS_VM_READ, FALSE, targetPID);
        if (!hProc) return 0;
        BYTE* buf = new BYTE[textSectionSize];
        if (!ReadProcessMemory(hProc, (LPCVOID)textBaseAddress, buf, textSectionSize, nullptr)) {
            delete[] buf; CloseHandle(hProc); return 0;
        }
        uint32_t h = HashBuffer(buf, textSectionSize);
        delete[] buf; CloseHandle(hProc); return h;
    }

public:
    static __forceinline void InitializeAndHash(HANDLE hProc, DWORD pid, DWORD_PTR baseAddr) {
        targetPID = pid;
        textBaseAddress = 0;
        textSectionSize = 0;
        baselineHash = 0;

        IMAGE_DOS_HEADER dosH;
        if (!ReadProcessMemory(hProc, (LPCVOID)baseAddr, &dosH, sizeof(dosH), nullptr)) return;

        IMAGE_NT_HEADERS ntH;
        if (!ReadProcessMemory(hProc, (LPCVOID)(baseAddr + dosH.e_lfanew), &ntH, sizeof(ntH), nullptr)) return;

        DWORD firstSectionAddr = dosH.e_lfanew + offsetof(IMAGE_NT_HEADERS, OptionalHeader) + ntH.FileHeader.SizeOfOptionalHeader;

        IMAGE_SECTION_HEADER secH;
        for (WORD i = 0; i < ntH.FileHeader.NumberOfSections; i++) {
            if (ReadProcessMemory(hProc, (LPCVOID)(baseAddr + firstSectionAddr + (i * sizeof(secH))), &secH, sizeof(secH), nullptr)) {
                if (strncmp((const char*)secH.Name, PCrypt(".text").c_str(), 5) == 0) {
                    textBaseAddress = baseAddr + secH.VirtualAddress;
                    textSectionSize = secH.Misc.VirtualSize;
                    BYTE* buf = new BYTE[textSectionSize];
                    if (ReadProcessMemory(hProc, (LPCVOID)textBaseAddress, buf, textSectionSize, nullptr)) {
                        baselineHash = HashBuffer(buf, textSectionSize);
                    }
                    delete[] buf;
                    return;
                }
            }
        }
    }

    static __forceinline void Start() {
        if (baselineHash == 0) return;

        isRunning = true;
        std::thread([]() {
            while (isRunning) {
                std::this_thread::sleep_for(std::chrono::seconds(3));
                uint32_t curr = CalculateRemoteHash();
                if (curr != 0 && curr != baselineHash) {
                    HANDLE hG = OpenProcess(PROCESS_TERMINATE, FALSE, targetPID);
                    if (hG) { TerminateProcess(hG, 0xDEAD); CloseHandle(hG); }
                    TerminateProcess(GetCurrentProcess(), 0xDEAD);
                }
            }
            }).detach();
    }

    static __forceinline void Stop() { isRunning = false; }
};