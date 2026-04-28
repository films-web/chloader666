#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <vector>

extern "C" {
#include "miniz.h"
}

class FairshotManager {
private:
    struct EnumData {
        DWORD processId;
        HWND hwnd;
    };

    static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
        EnumData& data = *(EnumData*)lParam;
        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);

        if (pid == data.processId && IsWindowVisible(hwnd) && GetConsoleWindow() != hwnd) {
            data.hwnd = hwnd;
            return FALSE;
        }
        return TRUE;
    }

    static HWND FindGameWindow(DWORD processId) {
        EnumData data = { processId, NULL };
        EnumWindows(EnumWindowsProc, (LPARAM)&data);
        return data.hwnd;
    }

public:
    static std::vector<uint8_t> CaptureGameWindow(DWORD gamePid) {
        HWND hWnd = FindGameWindow(gamePid);
        if (!hWnd) return {};

        if (IsIconic(hWnd)) {
            return {};
        }

        RECT clientRect;
        GetClientRect(hWnd, &clientRect);

        int width = clientRect.right - clientRect.left;
        int height = clientRect.bottom - clientRect.top;

        if (width <= 0 || height <= 0) return {};

        HDC hWindowDC = GetDC(hWnd);
        HDC hMemoryDC = CreateCompatibleDC(hWindowDC);
        HBITMAP hBitmap = CreateCompatibleBitmap(hWindowDC, width, height);
        HGDIOBJ old_obj = SelectObject(hMemoryDC, hBitmap);

        BitBlt(hMemoryDC, 0, 0, width, height, hWindowDC, 0, 0, SRCCOPY);

        BITMAPINFOHEADER bmi = { 0 };
        bmi.biSize = sizeof(BITMAPINFOHEADER);
        bmi.biPlanes = 1;
        bmi.biBitCount = 24;
        bmi.biWidth = width;
        bmi.biHeight = -height;
        bmi.biCompression = BI_RGB;
        bmi.biSizeImage = ((width * 3 + 3) & ~3) * height;

        BITMAPFILEHEADER bmf = { 0 };
        bmf.bfType = 0x4D42;
        bmf.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
        bmf.bfSize = bmf.bfOffBits + bmi.biSizeImage;

        std::vector<uint8_t> bmpBuffer(bmf.bfSize);
        memcpy(bmpBuffer.data(), &bmf, sizeof(BITMAPFILEHEADER));
        memcpy(bmpBuffer.data() + sizeof(BITMAPFILEHEADER), &bmi, sizeof(BITMAPINFOHEADER));

        GetDIBits(hWindowDC, hBitmap, 0, height,
            bmpBuffer.data() + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER),
            (BITMAPINFO*)&bmi, DIB_RGB_COLORS);

        SelectObject(hMemoryDC, old_obj);
        DeleteObject(hBitmap);
        DeleteDC(hMemoryDC);
        ReleaseDC(hWnd, hWindowDC);

        size_t compressedSize = 0;
        void* pCompressed = tdefl_compress_mem_to_heap(
            bmpBuffer.data(),
            bmpBuffer.size(),
            &compressedSize,
            TDEFL_DEFAULT_MAX_PROBES | TDEFL_WRITE_ZLIB_HEADER
        );

        std::vector<uint8_t> finalPayload;
        if (pCompressed) {
            finalPayload.assign((uint8_t*)pCompressed, (uint8_t*)pCompressed + compressedSize);
            mz_free(pCompressed);
        }

        return finalPayload;
    }
};