#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <thread>
#include <atomic>
#include <chrono>

class SelfIntegrity {
private:
    static inline std::atomic<bool> isRunning{ false };
    static inline uint32_t baselineHash = 0;
    static inline BYTE* textBase = nullptr;
    static inline size_t textSize = 0;

    static uint32_t Hash(const BYTE* d, size_t s) {
        uint32_t h = 0x811c9dc5;
        for (size_t i = 0; i < s; ++i) { h ^= d[i]; h *= 0x01000193; }
        return h;
    }

public:
    static void Start() {
        HMODULE mod = GetModuleHandleA(NULL);
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mod;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)mod + dos->e_lfanew);
        PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
            if (strncmp((const char*)sec->Name, ".text", 5) == 0) {
                textBase = (BYTE*)mod + sec->VirtualAddress;
                textSize = sec->Misc.VirtualSize; break;
            }
        }
        baselineHash = Hash(textBase, textSize);
        isRunning = true;
        std::thread([]() {
            while (isRunning) {
                std::this_thread::sleep_for(std::chrono::seconds(2));
                if (Hash(textBase, textSize) != baselineHash) TerminateProcess(GetCurrentProcess(), 0xDEAD);
            }
            }).detach();
    }
    static void Stop() { isRunning = false; }
};