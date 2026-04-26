#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <thread>
#include <atomic>
#include <chrono>

class AntiDebug {
private:
    // winternl.h exposes an incomplete PEB that is missing NtGlobalFlag and
    // ProcessHeap. Define the full x86 layout manually instead.
    struct PEB_FULL {
        BYTE  InheritedAddressSpace;        // 0x00
        BYTE  ReadImageFileExecOptions;     // 0x01
        BYTE  BeingDebugged;                // 0x02
        BYTE  BitField;                     // 0x03
        PVOID Mutant;                       // 0x04
        PVOID ImageBaseAddress;             // 0x08
        PVOID Ldr;                          // 0x0C
        PVOID ProcessParameters;            // 0x10
        PVOID SubSystemData;                // 0x14
        PVOID ProcessHeap;                  // 0x18
        PVOID FastPebLock;                  // 0x1C
        PVOID AtlThunkSListPtr;             // 0x20
        PVOID IFEOKey;                      // 0x24
        ULONG CrossProcessFlags;            // 0x28
        PVOID KernelCallbackTable;          // 0x2C
        ULONG SystemReserved;               // 0x30
        ULONG AtlThunkSListPtr32;           // 0x34
        PVOID ApiSetMap;                    // 0x38
        ULONG TlsExpansionCounter;          // 0x3C
        PVOID TlsBitmap;                    // 0x40
        ULONG TlsBitmapBits[2];             // 0x44
        PVOID ReadOnlySharedMemoryBase;     // 0x4C
        PVOID SharedData;                   // 0x50
        PVOID ReadOnlyStaticServerData;     // 0x54
        PVOID AnsiCodePageData;             // 0x58
        PVOID OemCodePageData;              // 0x5C
        PVOID UnicodeCaseTableData;         // 0x60
        ULONG NumberOfProcessors;           // 0x64
        ULONG NtGlobalFlag;                 // 0x68
    };

    static PEB_FULL* GetPEB() {
        return (PEB_FULL*)__readfsdword(0x30);
    }

    static bool CheckNtGlobalFlag() {
        return (GetPEB()->NtGlobalFlag & 0x70) != 0;
    }

    static bool CheckHeapFlags() {
        PVOID heap = GetPEB()->ProcessHeap;
        DWORD flags = *(DWORD*)((BYTE*)heap + 0x0C);
        DWORD forceFlags = *(DWORD*)((BYTE*)heap + 0x10);
        return ((flags & ~HEAP_GROWABLE) != 0) || (forceFlags != 0);
    }

    static bool CheckDebuggerPresent() {
        if (IsDebuggerPresent()) return true;
        BOOL isRemote = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemote);
        return isRemote == TRUE;
    }

    static bool CheckOutputDebugString() {
        SetLastError(0);
        OutputDebugStringA("x");
        return GetLastError() == 0;
    }

    static bool CheckHardwareBreakpoints() {
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (!GetThreadContext(GetCurrentThread(), &ctx)) return false;
        return (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3);
    }

    static bool IsBeingDebugged() {
        return CheckDebuggerPresent()
            || CheckNtGlobalFlag()
            || CheckHeapFlags()
            || CheckHardwareBreakpoints()
            || CheckOutputDebugString();
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