#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <string>
#include <vector>

#pragma comment(lib, "winhttp.lib")

class HttpUploader {
public:
    static bool Upload(const std::string& domain, const std::string& guid, const std::string& serverIp, const std::vector<uint8_t>& data) {
        if (data.empty()) return false;

        HINTERNET hSession = WinHttpOpen(L"CheatHaram AC/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return false;

        std::wstring wDomain(domain.begin(), domain.end());

        HINTERNET hConnect = WinHttpConnect(hSession, wDomain.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);

        if (hConnect) {
            HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/upload/fairshot",
                NULL, WINHTTP_NO_REFERER,
                WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);

            if (hRequest) {
                std::wstring wGuid(guid.begin(), guid.end());
                std::wstring wServer(serverIp.begin(), serverIp.end());

                std::wstring headers = L"Content-Type: application/octet-stream\r\n"
                    L"X-Client-GUID: " + wGuid + L"\r\n"
                    L"X-Server-IP: " + wServer + L"\r\n";

                if (WinHttpSendRequest(hRequest,
                    headers.c_str(), headers.length(),
                    (LPVOID)data.data(), data.size(), data.size(), 0)) {

                    WinHttpReceiveResponse(hRequest, NULL);

                    WinHttpCloseHandle(hRequest);
                    WinHttpCloseHandle(hConnect);
                    WinHttpCloseHandle(hSession);
                    return true;
                }
                WinHttpCloseHandle(hRequest);
            }
            WinHttpCloseHandle(hConnect);
        }
        WinHttpCloseHandle(hSession);
        return false;
    }
};