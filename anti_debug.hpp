#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <thread>
#include <atomic>
#include <chrono>

#include "poly_crypt.hpp"

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

    static __forceinline PEB_FULL* GetPEB() {
        return (PEB_FULL*)__readfsdword(0x30);
    }

    static __forceinline bool CheckNtGlobalFlag() {
        PEB_FULL* peb = GetPEB();
        if (!peb) return false;
        return (peb->NtGlobalFlag & 0x70) != 0;
    }

    static __forceinline bool CheckDebuggerPresent() {
        PEB_FULL* peb = GetPEB();
        if (peb && peb->BeingDebugged == 1) return true;
        BOOL isRemote = FALSE;
        HMODULE hKernel32 = GetModuleHandleA(PCrypt("kernel32.dll").c_str());
        if (hKernel32) {
            auto pCheckRemote = (BOOL(WINAPI*)(HANDLE, PBOOL))GetProcAddress(hKernel32, PCrypt("CheckRemoteDebuggerPresent").c_str());
            if (pCheckRemote) pCheckRemote(GetCurrentProcess(), &isRemote);
        }
        return isRemote == TRUE;
    }

    static __forceinline bool CheckHardwareBreakpoints() {
        bool found = false;
        HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hThreadSnap == INVALID_HANDLE_VALUE) return false;

        THREADENTRY32 te32;
        te32.dwSize = sizeof(THREADENTRY32);
        DWORD myPid = GetCurrentProcessId();

        if (Thread32First(hThreadSnap, &te32)) {
            do {
                if (te32.th32OwnerProcessID == myPid) {
                    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT, FALSE, te32.th32ThreadID);
                    if (hThread) {
                        CONTEXT ctx = {};
                        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                        if (GetThreadContext(hThread, &ctx)) {
                            if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
                                found = true;
                            }
                        }
                        CloseHandle(hThread);
                    }
                }
            } while (Thread32Next(hThreadSnap, &te32) && !found);
        }
        CloseHandle(hThreadSnap);
        return found;
    }

    static __forceinline bool IsBeingDebugged() {
        return CheckDebuggerPresent()
            || CheckHardwareBreakpoints()
            || CheckNtGlobalFlag();
    }

    [[noreturn]] static __forceinline void Terminate() {
        TerminateProcess(GetCurrentProcess(), 0xDEAD);
        __fastfail(0xDEAD);
    }

    static inline std::atomic<bool> isRunning{ false };

public:
    static __forceinline void Start(std::atomic<bool>& globalRunning) {
        isRunning = true;
        std::thread([&globalRunning]() {
            while (isRunning && globalRunning) {
                if (IsBeingDebugged()) Terminate();
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
            }).detach();
    }

    static __forceinline void Stop() { isRunning = false; }
};