#pragma once
#include <cstdint>
#include <string>

namespace ConstHash {
    constexpr uint32_t FNV_PRIME = 0x01000193;
    constexpr uint32_t FNV_OFFSET = 0x811c9dc5;

    constexpr uint32_t CompileTime(const char* str) {
        uint32_t hash = FNV_OFFSET;
        while (*str) { hash ^= static_cast<uint32_t>(*str++); hash *= FNV_PRIME; }
        return hash;
    }

    inline uint32_t RunTime(const std::string& str) {
        uint32_t hash = FNV_OFFSET;
        for (char c : str) { hash ^= static_cast<uint32_t>(c); hash *= FNV_PRIME; }
        return hash;
    }
}

#define CHash(str) std::integral_constant<uint32_t, ConstHash::CompileTime(str)>::value