#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <thread>
#include <atomic>
#include <chrono>

class AntiDebug {
private:
    struct PEB_FULL {
        BYTE  Reserved1[2];
        BYTE  BeingDebugged;
        BYTE  Reserved2[1];
        PVOID Reserved3[2];
        PVOID Ldr;
        PVOID ProcessParameters;
        PVOID Reserved4[3];
        PVOID AtlThunkSListPtr;
        PVOID Reserved5;
        ULONG Reserved6;
        PVOID Reserved7;
        ULONG Reserved8;
        ULONG AtlThunkSListPtr32;
        PVOID Reserved9[45];
        BYTE  Reserved10[96];
        PVOID PostProcessInitRoutine;
        BYTE  Reserved11[128];
        PVOID Reserved12[1];
        ULONG SessionId;
        ULONG NtGlobalFlag;
    };

    static PEB_FULL* GetPEB() {
        return (PEB_FULL*)__readfsdword(0x30);
    }

    static bool CheckNtGlobalFlag() {
        PEB_FULL* peb = GetPEB();
        if (!peb) return false;
        return (peb->NtGlobalFlag & 0x70) != 0;
    }

    static bool CheckDebuggerPresent() {
        if (IsDebuggerPresent()) return true;
        BOOL isRemote = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemote);
        return isRemote == TRUE;
    }

    static bool CheckHardwareBreakpoints() {
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        HANDLE hThread = GetCurrentThread();
        if (!GetThreadContext(hThread, &ctx)) return false;

        return (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0);
    }

    static bool IsBeingDebugged() {
        return CheckDebuggerPresent()
            || CheckHardwareBreakpoints()
            || CheckNtGlobalFlag();
    }

    [[noreturn]] static void Terminate() {
        TerminateProcess(GetCurrentProcess(), 0xDEAD);
        __fastfail(0xDEAD);
    }

    static inline std::atomic<bool> isRunning{ false };

public:
    static void Start(std::atomic<bool>& globalRunning) {
        isRunning = true;

        std::thread([&globalRunning]() {
            while (isRunning && globalRunning) {
                if (IsBeingDebugged()) Terminate();
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
            }).detach();
    }

    static void Stop() { isRunning = false; }
};