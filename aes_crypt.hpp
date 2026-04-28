#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include "crypto.hpp"

#pragma comment(lib, "bcrypt.lib")
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

class AESCrypt {
public:
    static std::string Encrypt(const std::string& plaintext, const std::string& keyStr) {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_KEY_HANDLE hKey = NULL;
        DWORD cbData = 0, cbKeyObject = 0, cbBlockLen = 0;
        DWORD cbCiphertext = 0;
        PBYTE pbKeyObject = NULL;
        std::string result = "";

        std::vector<BYTE> iv(16, 0);
        std::vector<BYTE> ivCopy;
        std::vector<BYTE> ciphertext;
        if (!NT_SUCCESS(BCryptGenRandom(NULL, iv.data(), 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG))) goto Cleanup;

        ivCopy = iv;

        if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0))) goto Cleanup;
        if (!NT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0))) goto Cleanup;
        if (!NT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbData, 0))) goto Cleanup;
        if (!NT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_BLOCK_LENGTH, (PBYTE)&cbBlockLen, sizeof(DWORD), &cbData, 0))) goto Cleanup;

        pbKeyObject = new BYTE[cbKeyObject];
        if (!NT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject, cbKeyObject, (PBYTE)keyStr.data(), (ULONG)keyStr.size(), 0))) goto Cleanup;

        if (!NT_SUCCESS(BCryptEncrypt(hKey, (PBYTE)plaintext.data(), (ULONG)plaintext.size(), NULL, iv.data(), 16, NULL, 0, &cbCiphertext, BCRYPT_BLOCK_PADDING))) goto Cleanup;

        ciphertext.resize(cbCiphertext);
        if (!NT_SUCCESS(BCryptEncrypt(hKey, (PBYTE)plaintext.data(), (ULONG)plaintext.size(), NULL, iv.data(), 16, ciphertext.data(), cbCiphertext, &cbCiphertext, BCRYPT_BLOCK_PADDING))) goto Cleanup;

        {
            std::vector<BYTE> finalPayload;
            finalPayload.insert(finalPayload.end(), ivCopy.begin(), ivCopy.end());
            finalPayload.insert(finalPayload.end(), ciphertext.begin(), ciphertext.end());
            result = Crypto::Base64Encode(finalPayload);
        }

    Cleanup:
        if (hKey) BCryptDestroyKey(hKey);
        if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
        if (pbKeyObject) delete[] pbKeyObject;
        return result;
    }

    static std::string Decrypt(const std::string& b64Payload, const std::string& keyStr) {
        std::vector<BYTE> rawData = Crypto::Base64Decode(b64Payload);
        if (rawData.size() <= 16) return "";

        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_KEY_HANDLE hKey = NULL;
        DWORD cbData = 0, cbKeyObject = 0, cbBlockLen = 0;
        DWORD cbPlaintext = 0;
        PBYTE pbKeyObject = NULL;
        std::string result = "";

        std::vector<BYTE> iv(rawData.begin(), rawData.begin() + 16);
        std::vector<BYTE> ciphertext(rawData.begin() + 16, rawData.end());
        std::vector<BYTE> plaintext;

        if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0))) goto Cleanup;
        if (!NT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0))) goto Cleanup;
        if (!NT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbData, 0))) goto Cleanup;
        if (!NT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_BLOCK_LENGTH, (PBYTE)&cbBlockLen, sizeof(DWORD), &cbData, 0))) goto Cleanup;

        pbKeyObject = new BYTE[cbKeyObject];
        if (!NT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject, cbKeyObject, (PBYTE)keyStr.data(), (ULONG)keyStr.size(), 0))) goto Cleanup;

        if (!NT_SUCCESS(BCryptDecrypt(hKey, ciphertext.data(), (ULONG)ciphertext.size(), NULL, iv.data(), 16, NULL, 0, &cbPlaintext, BCRYPT_BLOCK_PADDING))) goto Cleanup;

        plaintext.resize(cbPlaintext);
        if (NT_SUCCESS(BCryptDecrypt(hKey, ciphertext.data(), (ULONG)ciphertext.size(), NULL, iv.data(), 16, plaintext.data(), cbPlaintext, &cbPlaintext, BCRYPT_BLOCK_PADDING))) {
            result = std::string((char*)plaintext.data(), cbPlaintext);
        }

    Cleanup:
        if (hKey) BCryptDestroyKey(hKey);
        if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
        if (pbKeyObject) delete[] pbKeyObject;
        return result;
    }
};