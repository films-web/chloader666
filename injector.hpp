#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <filesystem>

class Injector {
public:
    static DWORD GetProcessIdByName(const std::string& processName) {
        DWORD processId = 0;
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W processEntry;
            processEntry.dwSize = sizeof(PROCESSENTRY32W);

            if (Process32FirstW(hSnapshot, &processEntry)) {
                do {
                    std::wstring ws(processEntry.szExeFile);
                    std::string currentExeName(ws.begin(), ws.end());
                    if (!_stricmp(currentExeName.c_str(), processName.c_str())) {
                        processId = processEntry.th32ProcessID;
                        break;
                    }
                } while (Process32NextW(hSnapshot, &processEntry));
            }
            CloseHandle(hSnapshot);
        }
        return processId;
    }

    static bool LaunchAndInject(const std::string& exePath, const std::string& dllPath) {
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };
        std::string gameDir = std::filesystem::path(exePath).parent_path().string();

        if (!CreateProcessA(
            exePath.c_str(),
            NULL,
            NULL,
            NULL,
            FALSE,
            CREATE_SUSPENDED,
            NULL,
            gameDir.c_str(),
            &si,
            &pi)) return false;

        void* allocMem = VirtualAllocEx(pi.hProcess, nullptr, dllPath.length() + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!allocMem) { TerminateProcess(pi.hProcess, 1); return false; }

        if (!WriteProcessMemory(pi.hProcess, allocMem, dllPath.c_str(), dllPath.length() + 1, nullptr)) {
            VirtualFreeEx(pi.hProcess, allocMem, 0, MEM_RELEASE);
            TerminateProcess(pi.hProcess, 1);
            return false;
        }

        FARPROC loadLibAddr = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
        HANDLE hThread = CreateRemoteThread(pi.hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)loadLibAddr, allocMem, 0, nullptr);

        if (!hThread) {
            VirtualFreeEx(pi.hProcess, allocMem, 0, MEM_RELEASE);
            TerminateProcess(pi.hProcess, 1);
            return false;
        }

        WaitForSingleObject(hThread, INFINITE);

        DWORD exitCode = 0;
        GetExitCodeThread(hThread, &exitCode);
        if (exitCode == 0) {
            VirtualFreeEx(pi.hProcess, allocMem, 0, MEM_RELEASE);
            CloseHandle(hThread);
            TerminateProcess(pi.hProcess, 1);
            return false;
        }

        VirtualFreeEx(pi.hProcess, allocMem, 0, MEM_RELEASE);
        CloseHandle(hThread);

        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return true;
    }
};