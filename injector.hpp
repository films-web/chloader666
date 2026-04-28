#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <filesystem>
#include <functional>

class Injector {
public:
    static bool IsProcessRunning(DWORD pid) {
        if (pid == 0) return false;
        HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, pid);
        if (process == NULL) return false;
        DWORD ret = WaitForSingleObject(process, 0);
        CloseHandle(process);
        return ret == WAIT_TIMEOUT;
    }

    static DWORD LaunchAndInject(
        const std::string& exePath,
        const std::string& dllPath,
        std::function<void(HANDLE hProc, DWORD pid, DWORD_PTR baseAddr)> onPreResume = nullptr
    ) {
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };
        std::string gameDir = std::filesystem::path(exePath).parent_path().string();

        if (!CreateProcessA(exePath.c_str(), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, gameDir.c_str(), &si, &pi)) return 0;

        void* allocMem = VirtualAllocEx(pi.hProcess, nullptr, dllPath.length() + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!allocMem) { TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hThread); CloseHandle(pi.hProcess); return 0; }

        if (!WriteProcessMemory(pi.hProcess, allocMem, dllPath.c_str(), dllPath.length() + 1, nullptr)) {
            VirtualFreeEx(pi.hProcess, allocMem, 0, MEM_RELEASE); TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hThread); CloseHandle(pi.hProcess); return 0;
        }

        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        if (!hKernel32) {
            VirtualFreeEx(pi.hProcess, allocMem, 0, MEM_RELEASE); TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hThread); CloseHandle(pi.hProcess); return 0;
        }

        FARPROC loadLibAddr = GetProcAddress(hKernel32, "LoadLibraryA");
        if (!loadLibAddr) {
            VirtualFreeEx(pi.hProcess, allocMem, 0, MEM_RELEASE); TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hThread); CloseHandle(pi.hProcess); return 0;
        }

        HANDLE hThread = CreateRemoteThread(pi.hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)loadLibAddr, allocMem, 0, nullptr);
        if (!hThread) {
            VirtualFreeEx(pi.hProcess, allocMem, 0, MEM_RELEASE); TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hThread); CloseHandle(pi.hProcess); return 0;
        }

        WaitForSingleObject(hThread, INFINITE);

        DWORD exitCode = 0;
        GetExitCodeThread(hThread, &exitCode);
        if (exitCode == 0) {
            VirtualFreeEx(pi.hProcess, allocMem, 0, MEM_RELEASE); CloseHandle(hThread); TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hThread); CloseHandle(pi.hProcess); return 0;
        }

        if (onPreResume) {
            onPreResume(pi.hProcess, pi.dwProcessId, exitCode);
        }

        VirtualFreeEx(pi.hProcess, allocMem, 0, MEM_RELEASE);
        CloseHandle(hThread);

        ResumeThread(pi.hThread);

        DWORD pid = pi.dwProcessId;
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);

        return pid;
    }

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
};