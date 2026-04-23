#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <urlmon.h>
#include <wininet.h>

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "wininet.lib")

class Downloader {
public:
    static bool DownloadHttps(const std::string& url, const std::string& destinationPath) {

        DeleteUrlCacheEntryA(url.c_str());

        HRESULT res = URLDownloadToFileA(
            NULL,
            url.c_str(),
            destinationPath.c_str(),
            0,
            NULL
        );

        return (res == S_OK);
    }
};