#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <string>
#include <fstream>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

#include "poly_crypt.hpp"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace Crypto {
    __forceinline uint32_t HashFNV(const BYTE* d, size_t s) {
        uint32_t h = 0x811c9dc5u;
        for (size_t i = 0; i < s; ++i) { h ^= d[i]; h *= 0x01000193u; }
        return h;
    }

    __forceinline uint32_t HashSum(const BYTE* d, size_t s) {
        uint32_t h = 0u;
        for (size_t i = 0; i < s; ++i) {
            h += d[i];
            h ^= (h << 5) | (h >> 27);
        }
        return h;
    }

    __forceinline std::string Base64Encode(const std::vector<unsigned char>& data) {
        auto lookup = PCrypt("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
        std::string out;
        int val = 0, valb = -6;
        for (unsigned char c : data) {
            val = (val << 8) + c;
            valb += 8;
            while (valb >= 0) {
                out.push_back(lookup.c_str()[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        if (valb > -6) out.push_back(lookup.c_str()[((val << 8) >> (valb + 8)) & 0x3F]);
        while (out.size() % 4) out.push_back('=');
        return out;
    }

    __forceinline std::vector<unsigned char> Base64Decode(const std::string& in) {
        // ENCRYPTED: Hide the Base64 lookup table.
        auto b64 = PCrypt("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
        std::vector<unsigned char> out;
        std::vector<int> T(256, -1);
        for (int i = 0; i < 64; i++) T[b64.c_str()[i]] = i;
        int val = 0, valb = -8;
        for (unsigned char c : in) {
            if (T[c] == -1) break;
            val = (val << 6) + T[c];
            valb += 6;
            if (valb >= 0) {
                out.push_back(char((val >> valb) & 0xFF));
                valb -= 8;
            }
        }
        return out;
    }

    __forceinline std::string GenerateSHA256Key(const std::string& message, const std::string& key) {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;
        DWORD cbHashObject = 0, cbData = 0;
        PBYTE pbHashObject = NULL, pbHash = NULL;
        std::string hexResult = "";

        if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG))) return "";
        if (!NT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0))) goto Cleanup;
        if (!NT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbData, sizeof(DWORD), &cbData, 0))) goto Cleanup;

        pbHashObject = new BYTE[cbHashObject];
        pbHash = new BYTE[cbData];

        if (!NT_SUCCESS(BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, (PUCHAR)key.data(), (ULONG)key.size(), 0))) goto Cleanup;
        if (!NT_SUCCESS(BCryptHashData(hHash, (PUCHAR)message.data(), (ULONG)message.size(), 0))) goto Cleanup;
        if (!NT_SUCCESS(BCryptFinishHash(hHash, pbHash, cbData, 0))) goto Cleanup;

        for (DWORD i = 0; i < cbData; i++) {
            char buf[3];
            snprintf(buf, sizeof(buf), PCrypt("%02x").c_str(), pbHash[i]);
            hexResult += buf;
        }

    Cleanup:
        if (hHash) BCryptDestroyHash(hHash);
        if (pbHashObject) delete[] pbHashObject;
        if (pbHash) delete[] pbHash;
        if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);

        return hexResult;
    }

    __forceinline std::string CalculateSHA256String(const std::string& input) {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;
        DWORD cbHashObject = 0, cbData = 0;
        PBYTE pbHashObject = NULL, pbHash = NULL;
        std::string hexResult = "";

        if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) return "";
        if (!NT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0))) goto Cleanup;
        if (!NT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbData, sizeof(DWORD), &cbData, 0))) goto Cleanup;

        pbHashObject = new BYTE[cbHashObject];
        pbHash = new BYTE[cbData];

        if (!NT_SUCCESS(BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0))) goto Cleanup;
        if (!NT_SUCCESS(BCryptHashData(hHash, (PUCHAR)input.data(), (ULONG)input.size(), 0))) goto Cleanup;
        if (!NT_SUCCESS(BCryptFinishHash(hHash, pbHash, cbData, 0))) goto Cleanup;

        for (DWORD i = 0; i < cbData; i++) {
            char buf[3];
            snprintf(buf, sizeof(buf), PCrypt("%02x").c_str(), pbHash[i]);
            hexResult += buf;
        }

    Cleanup:
        if (hHash) BCryptDestroyHash(hHash);
        if (pbHashObject) delete[] pbHashObject;
        if (pbHash) delete[] pbHash;
        if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);

        return hexResult;
    }

    __forceinline std::string CalculateSHA256File(const std::string& filepath) {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;
        DWORD cbHashObject = 0, cbData = 0;
        PBYTE pbHashObject = NULL, pbHash = NULL;
        std::string hexResult = "";

        std::ifstream file(filepath, std::ios::binary);
        if (!file) return "";

        if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) return "";
        if (!NT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0))) goto Cleanup;
        if (!NT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbData, sizeof(DWORD), &cbData, 0))) goto Cleanup;

        pbHashObject = new BYTE[cbHashObject];
        pbHash = new BYTE[cbData];

        if (!NT_SUCCESS(BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0))) goto Cleanup;

        {
            const int bufSize = 32768;
            std::vector<char> buffer(bufSize);
            while (file.read(buffer.data(), bufSize)) {
                if (!NT_SUCCESS(BCryptHashData(hHash, (PUCHAR)buffer.data(), bufSize, 0))) goto Cleanup;
            }
            if (file.gcount() > 0) {
                if (!NT_SUCCESS(BCryptHashData(hHash, (PUCHAR)buffer.data(), (ULONG)file.gcount(), 0))) goto Cleanup;
            }
        }

        if (!NT_SUCCESS(BCryptFinishHash(hHash, pbHash, cbData, 0))) goto Cleanup;

        for (DWORD i = 0; i < cbData; i++) {
            char buf[3];
            snprintf(buf, sizeof(buf), PCrypt("%02x").c_str(), pbHash[i]);
            hexResult += buf;
        }

    Cleanup:
        if (hHash) BCryptDestroyHash(hHash);
        if (pbHashObject) delete[] pbHashObject;
        if (pbHash) delete[] pbHash;
        if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);

        return hexResult;
    }
}