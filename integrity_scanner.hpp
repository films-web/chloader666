#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <vector>
#include <filesystem>
#include <algorithm> 
#include <unordered_set>

#include "crypto.hpp"
#include "const_hash.hpp"
#include "poly_crypt.hpp"

extern "C" {
#include "miniz.h"
}

class IntegrityScanner {
private:
    static inline void ToLowerInPlace(std::string& str) {
        for (char& c : str) { c = std::tolower(static_cast<unsigned char>(c)); }
    }

public:
    static std::string DeepScanPk3(const std::string& filepath) {
        mz_zip_archive zip_archive;
        memset(&zip_archive, 0, sizeof(zip_archive));
        if (!mz_zip_reader_init_file(&zip_archive, filepath.c_str(), 0)) return "";

        static const std::unordered_set<uint32_t> bannedFileHashes = {
            CHash("average_armor.shader"),
            CHash("suit_long_coat.shader"),
            CHash("average_sleeves.shader"),
            CHash("suit_sleeves.shader"),
            CHash("female_skirt.shader"),
            CHash("chem_suit.shader"),
            CHash("fat.shader"),
            CHash("female_armor.shader"),
            CHash("female_pants.shader"),
            CHash("bolt_ons.shader"),
            CHash("weapons.shader"),
            CHash("sof2mp_cgame.qvm")
        };

        std::string detected = "";
        int fileCount = (int)mz_zip_reader_get_num_files(&zip_archive);
        for (int i = 0; i < fileCount; i++) {
            mz_zip_archive_file_stat file_stat;
            mz_zip_reader_file_stat(&zip_archive, i, &file_stat);
            std::string baseName = std::filesystem::path(file_stat.m_filename).filename().string();
            ToLowerInPlace(baseName);

            bool isGlm = (baseName.length() >= 4 && baseName.substr(baseName.length() - 4) == PCrypt(".glm").c_str());

            if (isGlm || bannedFileHashes.count(ConstHash::RunTime(baseName))) {
                detected = baseName;
                break;
            }
        }
        mz_zip_reader_end(&zip_archive);
        return detected;
    }

    static std::string VerifyGameFolder(const std::string& gameRoot, const std::vector<std::string>& whitelist) {
        if (!std::filesystem::exists(gameRoot)) return PCrypt("Invalid_Path").c_str();

        std::unordered_set<std::string> fastWhitelist;
        for (auto h : whitelist) { ToLowerInPlace(h); fastWhitelist.insert(h); }

        for (const auto& entry : std::filesystem::recursive_directory_iterator(gameRoot)) {
            if (entry.is_regular_file() && entry.path().extension() == PCrypt(".pk3").c_str()) {
                std::string hash = Crypto::CalculateSHA256File(entry.path().string());
                ToLowerInPlace(hash);
                if (!fastWhitelist.count(hash)) {
                    std::string internal = DeepScanPk3(entry.path().string());
                    if (!internal.empty()) return entry.path().filename().string();
                }
            }
        }
        return "";
    }
};