#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <array>

constexpr char PolyKey() {
    return (__TIME__[7] - '0') ^ (__TIME__[6] - '0') ^ 0x42;
}

template <size_t Size>
struct SecureBuffer {
    char data[Size]{};
    __forceinline ~SecureBuffer() { SecureZeroMemory(data, Size); }
    __forceinline operator const char* () const { return data; }
    __forceinline const char* c_str() const { return data; }
};

template <size_t N, int Method>
class PolyCrypt {
private:
    std::array<char, N> buffer{};
    char key;

public:
    consteval PolyCrypt(const char(&str)[N]) : key(PolyKey()) {
        for (size_t i = 0; i < N; ++i) {
            char idx = static_cast<char>(i);
            if constexpr (Method % 3 == 0) buffer[i] = str[i] ^ (key + idx);
            else if constexpr (Method % 3 == 1) buffer[i] = str[i] + (key ^ idx);
            else buffer[i] = str[i] - key + idx;
        }
    }

    __forceinline auto decrypt() const {
        SecureBuffer<N> decrypted{};
        for (size_t i = 0; i < N - 1; ++i) {
            char idx = static_cast<char>(i);
            if constexpr (Method % 3 == 0) decrypted.data[i] = buffer[i] ^ (key + idx);
            else if constexpr (Method % 3 == 1) decrypted.data[i] = buffer[i] - (key ^ idx);
            else decrypted.data[i] = buffer[i] + key - idx;
        }
        decrypted.data[N - 1] = '\0';
        return decrypted;
    }
};

#define PCrypt(str) (PolyCrypt<sizeof(str), __COUNTER__>(str).decrypt())