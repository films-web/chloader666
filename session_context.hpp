#pragma once
#include <string>
#include <vector>
#include <atomic>
#include <mutex>
#include <utility>

#include "event_bus.hpp"
#include "poly_crypt.hpp"

class SessionContext {
public:
    std::atomic<bool> isAuthenticated{ false };
    std::atomic<bool> hasReceivedWhitelist{ false };
    std::atomic<bool> hasReceivedDllInfo{ false };
    std::atomic<bool> isGameFolderClean{ false };
    std::atomic<bool> isInjected{ false };
    std::atomic<bool> isGameConnected{ false };
    std::atomic<DWORD> gamePid{ 0 };

    __forceinline void SetWhitelist(const std::vector<std::string>& hashes) {
        std::lock_guard<std::mutex> lock(configMutex);
        serverWhitelist = hashes;
    }
    __forceinline std::vector<std::string> GetWhitelist() {
        std::lock_guard<std::mutex> lock(configMutex);
        return serverWhitelist;
    }

    __forceinline void SetDllInfo(const std::string& url, const std::string& hash, const std::string& name) {
        std::lock_guard<std::mutex> lock(configMutex);
        dllUrl = url;
        dllExpectedHash = hash;
        dllName = name;
    }

    __forceinline std::string GetDllUrl() { std::lock_guard<std::mutex> lock(configMutex); return dllUrl; }
    __forceinline std::string GetDllHash() { std::lock_guard<std::mutex> lock(configMutex); return dllExpectedHash; }
    __forceinline std::string GetDllName() { std::lock_guard<std::mutex> lock(configMutex); return dllName; }

    __forceinline void SetTargetServer(const std::string& ip) {
        std::lock_guard<std::mutex> lock(configMutex);
        targetServer = ip;
    }
    __forceinline std::string GetTargetServer() {
        std::lock_guard<std::mutex> lock(configMutex);
        return targetServer;
    }

    __forceinline void SetUiStatus(UiStatusType type, const std::string& status) {
        std::lock_guard<std::mutex> lock(uiMutex);
        uiStatusType = type;
        uiStatus = status;
    }

    __forceinline std::pair<UiStatusType, std::string> GetUiStatus() {
        std::lock_guard<std::mutex> lock(uiMutex);
        return { uiStatusType, uiStatus };
    }

    __forceinline void SetServerGuid(const std::string& guid) {
        std::lock_guard<std::mutex> lock(uiMutex);
        serverGuid = guid;
    }

    __forceinline std::string GetServerGuid() {
        std::lock_guard<std::mutex> lock(uiMutex);
        return serverGuid;
    }

private:
    std::mutex configMutex;
    std::vector<std::string> serverWhitelist;
    std::string dllUrl;
    std::string dllExpectedHash;
    std::string dllName;
    std::string targetServer;

    std::mutex uiMutex;
    UiStatusType uiStatusType = UiStatusType::INFO_STATE;

    std::string uiStatus = PCrypt("Initializing...").c_str();
    std::string serverGuid = PCrypt("-").c_str();
};