#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <thread>
#include <atomic>
#include <chrono>
#include <random>

#include "crypto.hpp"

class SelfIntegrity {
private:
    static inline std::atomic<bool>     isRunning{ false };

    static inline std::atomic<uint32_t> storedFnvA{ 0 };
    static inline std::atomic<uint32_t> storedSumA{ 0 };
    static inline std::atomic<uint32_t> storedFnvB{ 0 };
    static inline std::atomic<uint32_t> storedSumB{ 0 };
    static inline uint32_t              maskA{ 0 };
    static inline uint32_t              maskB{ 0 };

    static inline BYTE* textBase{ nullptr };
    static inline size_t textSize{ 0 };

    static bool LocateTextSection() {
        HMODULE mod = GetModuleHandleA(NULL);
        if (!mod) return false;
        auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(mod);
        auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
            reinterpret_cast<BYTE*>(mod) + dos->e_lfanew);
        auto* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
            if (strncmp(reinterpret_cast<const char*>(sec->Name), ".text", 5) == 0) {
                textBase = reinterpret_cast<BYTE*>(mod) + sec->VirtualAddress;
                textSize = sec->Misc.VirtualSize;
                return true;
            }
        }
        return false;
    }

    static void DeriveMasks() {
        volatile uintptr_t stackVar = 0xBEEF1234;
        maskA = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&stackVar))
            ^ 0xA5A5A5A5u;
        maskB = static_cast<uint32_t>(GetTickCount64() & 0xFFFFFFFFu)
            ^ 0x5A5A5A5Au;
        if (maskA == 0) maskA = 0xDEADC0DEu;
        if (maskB == 0) maskB = 0xC0DEBABEu;
    }

    [[noreturn]] static void Terminate() {
        TerminateProcess(GetCurrentProcess(), 0xDEAD);
        __fastfail(0xDEAD);
    }

    static bool Verify() {
        uint32_t currentFnv = Crypto::HashFNV(textBase, textSize);
        uint32_t currentSum = Crypto::HashSum(textBase, textSize);

        uint32_t baselineFnvA = storedFnvA.load(std::memory_order_relaxed) ^ maskA;
        uint32_t baselineSumA = storedSumA.load(std::memory_order_relaxed) ^ maskA;
        uint32_t baselineFnvB = storedFnvB.load(std::memory_order_relaxed) ^ maskB;
        uint32_t baselineSumB = storedSumB.load(std::memory_order_relaxed) ^ maskB;

        if (baselineFnvA != baselineFnvB) return false;
        if (baselineSumA != baselineSumB) return false;
        if (currentFnv != baselineFnvA)   return false;
        if (currentSum != baselineSumA)   return false;

        return true;
    }

public:
    static void Start() {
        if (!LocateTextSection()) return;

        DeriveMasks();

        uint32_t fnv = Crypto::HashFNV(textBase, textSize);
        uint32_t sum = Crypto::HashSum(textBase, textSize);

        storedFnvA.store(fnv ^ maskA, std::memory_order_relaxed);
        storedSumA.store(sum ^ maskA, std::memory_order_relaxed);
        storedFnvB.store(fnv ^ maskB, std::memory_order_relaxed);
        storedSumB.store(sum ^ maskB, std::memory_order_relaxed);

        if (!Verify()) Terminate();

        isRunning = true;

        std::thread([]() {
            uint32_t seed = static_cast<uint32_t>(GetTickCount64() & 0xFFFFFFFFu)
                ^ static_cast<uint32_t>(reinterpret_cast<uintptr_t>(textBase));
            std::mt19937 rng(seed);
            std::uniform_int_distribution<int> jitter(1500, 4500);

            while (isRunning) {
                std::this_thread::sleep_for(std::chrono::milliseconds(jitter(rng)));
                if (!isRunning) break;
                if (!Verify()) Terminate();
            }
            }).detach();
    }

    static void Stop() { isRunning = false; }
};