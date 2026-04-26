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

enum class ScanResult {
    CLEAN,
    INVALID_PATH,
    HACK_DETECTED
};

struct ScanReport {
    ScanResult  result;
    std::string detectedFile;
};

class IntegrityScanner {
private:
    static void ToLowerInPlace(std::string& str) {
        for (char& c : str) c = static_cast<char>(
            std::tolower(static_cast<unsigned char>(c)));
    }

    static const std::unordered_set<uint32_t>& BannedNames() {
        static const std::unordered_set<uint32_t> s = {
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
            CHash("sof2mp_cgame.qvm"),
        };
        return s;
    }


    static const std::unordered_set<uint32_t>& BannedExtensions() {
        static const std::unordered_set<uint32_t> s = {
            CHash(".glm"),
            CHash(".dll"),
            CHash(".exe"),
        };
        return s;
    }

    static ScanReport DeepScanPk3(const std::string& filepath) {
        mz_zip_archive zip{};
        if (!mz_zip_reader_init_file(&zip, filepath.c_str(), 0)) {
            return { ScanResult::HACK_DETECTED, filepath };
        }

        const auto& bannedNames = BannedNames();
        const auto& bannedExts = BannedExtensions();

        ScanReport report = { ScanResult::CLEAN, "" };

        int fileCount = static_cast<int>(mz_zip_reader_get_num_files(&zip));
        for (int i = 0; i < fileCount; ++i) {
            mz_zip_archive_file_stat stat{};
            if (!mz_zip_reader_file_stat(&zip, i, &stat)) continue;

            std::string baseName =
                std::filesystem::path(stat.m_filename).filename().string();
            ToLowerInPlace(baseName);

            if (bannedNames.count(ConstHash::RunTime(baseName))) {
                report = { ScanResult::HACK_DETECTED, baseName };
                break;
            }

            std::string ext =
                std::filesystem::path(stat.m_filename).extension().string();
            ToLowerInPlace(ext);

            if (!ext.empty() && bannedExts.count(ConstHash::RunTime(ext))) {
                report = { ScanResult::HACK_DETECTED, baseName };
                break;
            }
        }

        mz_zip_reader_end(&zip);
        return report;
    }

public:
    static ScanReport VerifyGameFolder(const std::string& gameRoot,
        const std::vector<std::string>& whitelist) {
        if (!std::filesystem::exists(gameRoot))
            return { ScanResult::INVALID_PATH, gameRoot };

        static const std::string pk3Ext = []() {
            return std::string(PCrypt(".pk3").c_str());
            }();

        std::unordered_set<std::string> fastWhitelist;
        fastWhitelist.reserve(whitelist.size());
        for (auto h : whitelist) { ToLowerInPlace(h); fastWhitelist.insert(h); }

        std::filesystem::recursive_directory_iterator iter(
            gameRoot,
            std::filesystem::directory_options::skip_permission_denied);

        for (auto it = std::filesystem::begin(iter);
            it != std::filesystem::end(iter); ) {
            try {
                const auto& entry = *it;

                if (!entry.is_regular_file() ||
                    entry.path().extension().string() != pk3Ext) {
                    ++it;
                    continue;
                }

                std::string hash = Crypto::CalculateSHA256File(
                    entry.path().string());
                ToLowerInPlace(hash);

                if (hash.empty()) {
                    return { ScanResult::HACK_DETECTED,
                             entry.path().filename().string() };
                }

                if (fastWhitelist.count(hash)) {
                    ++it;
                    continue;
                }

                ScanReport inner = DeepScanPk3(entry.path().string());
                if (inner.result == ScanResult::HACK_DETECTED) {
                    return { ScanResult::HACK_DETECTED,
                             entry.path().filename().string() };
                }

                ++it;
            }
            catch (const std::filesystem::filesystem_error&) {
                ++it;
            }
        }

        return { ScanResult::CLEAN, "" };
    }
};