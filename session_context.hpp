#pragma once
#include <string>
#include <vector>
#include <atomic>
#include <mutex>
#include <utility>
#include "event_bus.hpp"

class SessionContext {
public:
    std::atomic<bool> isAuthenticated{ false };
    std::atomic<bool> hasReceivedWhitelist{ false };
    std::atomic<bool> hasReceivedDllInfo{ false };
    std::atomic<bool> isGameFolderClean{ false };
    std::atomic<bool> isInjected{ false };
    std::atomic<bool> isGameConnected{ false };

    void SetWhitelist(const std::vector<std::string>& hashes) {
        std::lock_guard<std::mutex> lock(configMutex);
        serverWhitelist = hashes;
    }
    std::vector<std::string> GetWhitelist() {
        std::lock_guard<std::mutex> lock(configMutex);
        return serverWhitelist;
    }

    void SetDllInfo(const std::string& url, const std::string& hash, const std::string& name) {
        std::lock_guard<std::mutex> lock(configMutex);
        dllUrl = url;
        dllExpectedHash = hash;
        dllName = name;
    }

    std::string GetDllUrl() { std::lock_guard<std::mutex> lock(configMutex); return dllUrl; }
    std::string GetDllHash() { std::lock_guard<std::mutex> lock(configMutex); return dllExpectedHash; }
    std::string GetDllName() { std::lock_guard<std::mutex> lock(configMutex); return dllName; }

    void SetTargetServer(const std::string& ip) {
        std::lock_guard<std::mutex> lock(configMutex);
        targetServer = ip;
    }
    std::string GetTargetServer() {
        std::lock_guard<std::mutex> lock(configMutex);
        return targetServer;
    }

    void SetUiStatus(UiStatusType type, const std::string& status) {
        std::lock_guard<std::mutex> lock(uiMutex);
        uiStatusType = type;
        uiStatus = status;
    }

    std::pair<UiStatusType, std::string> GetUiStatus() {
        std::lock_guard<std::mutex> lock(uiMutex);
        return { uiStatusType, uiStatus };
    }

    void SetServerGuid(const std::string& guid) {
        std::lock_guard<std::mutex> lock(uiMutex);
        serverGuid = guid;
    }

    std::string GetServerGuid() {
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
    std::string uiStatus = "Initializing...";
    std::string serverGuid = "-";
};