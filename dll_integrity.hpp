#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
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
    static inline std::string targetDllName;
    static inline DWORD_PTR textBaseAddress = 0;
    static inline DWORD textSectionSize = 0;

    static std::wstring ToWide(const std::string& s) {
        return std::wstring(s.begin(), s.end());
    }

    static uint32_t HashBuffer(const BYTE* data, size_t size) {
        uint32_t hash = 0x811c9dc5;
        for (size_t i = 0; i < size; ++i) { hash ^= data[i]; hash *= 0x01000193; }
        return hash;
    }

    static bool InitializeRemoteSection() {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, targetPID);
        if (hSnap == INVALID_HANDLE_VALUE) return false;

        MODULEENTRY32W ME32; // Use Wide version
        ME32.dwSize = sizeof(ME32);
        bool found = false;
        BYTE* dllBase = nullptr;
        std::wstring wideTarget = ToWide(targetDllName);

        if (Module32FirstW(hSnap, &ME32)) {
            do {
                if (_wcsicmp(ME32.szModule, wideTarget.c_str()) == 0) {
                    dllBase = ME32.modBaseAddr; found = true; break;
                }
            } while (Module32NextW(hSnap, &ME32));
        }
        CloseHandle(hSnap);
        if (!found) return false;

        HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, targetPID);
        if (!hProc) return false;

        IMAGE_DOS_HEADER dosH;
        ReadProcessMemory(hProc, dllBase, &dosH, sizeof(dosH), nullptr);

        IMAGE_NT_HEADERS ntH; // This is an object
        ReadProcessMemory(hProc, dllBase + dosH.e_lfanew, &ntH, sizeof(ntH), nullptr);

        // Find the start of the section headers
        DWORD firstSectionAddr = dosH.e_lfanew + offsetof(IMAGE_NT_HEADERS, OptionalHeader) + ntH.FileHeader.SizeOfOptionalHeader;

        IMAGE_SECTION_HEADER secH;
        for (WORD i = 0; i < ntH.FileHeader.NumberOfSections; i++) {
            ReadProcessMemory(hProc, dllBase + firstSectionAddr + (i * sizeof(secH)), &secH, sizeof(secH), nullptr);

            // Compare section name
            if (strncmp((const char*)secH.Name, PCrypt(".text").c_str(), 5) == 0) {
                textBaseAddress = (DWORD_PTR)(dllBase + secH.VirtualAddress);
                textSectionSize = secH.Misc.VirtualSize;
                CloseHandle(hProc); return true;
            }
        }
        CloseHandle(hProc); return false;
    }

    static uint32_t CalculateRemoteHash() {
        if (textBaseAddress == 0) return 0;
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
    static void Start(DWORD pid, const std::string& name) {
        targetPID = pid; targetDllName = name; isRunning = true;
        std::thread([]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(2500));
            if (!InitializeRemoteSection()) return;
            baselineHash = CalculateRemoteHash();
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
    static void Stop() { isRunning = false; }
};