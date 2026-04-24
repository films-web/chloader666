#pragma once
#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <functional>
#include <unordered_map>
#include <vector>
#include <variant>
#include <string>
#include <utility>

enum class UiStatusType {
    INFO_STATE,
    LOADING,
    SUCCESS,
    ACTIVE,
    ERROR_STATE
};

enum class EventType {
    UI_STATUS_UPDATE,
    AUTH_SUCCESS,
    AUTH_FAILED,
    WHITELIST_RECEIVED,
    PAYLOAD_INFO_RECEIVED,
    START_SCAN,
    SCAN_COMPLETED,
    SCAN_FAILED,
    INJECT_PAYLOAD,
    INJECTION_SUCCESS,
    CRASH_REQUESTED,
    URL_CONNECT_REQUESTED,
    SET_GUID_REQUESTED,
    PLAYER_LIST_RECEIVED,
    SHUTDOWN_REQUESTED
};

struct Event {
    EventType type;
    std::variant<std::monostate, std::string, std::vector<std::string>, std::pair<UiStatusType, std::string>> payload;
};

class EventBus {
public:
    using SubscriberCallback = std::function<void(const Event&)>;

    void Publish(const Event& event) {
        {
            std::lock_guard<std::mutex> lock(queueMutex);
            eventQueue.push(event);
        }
        queueCondition.notify_one();
    }

    void Subscribe(EventType type, SubscriberCallback callback) {
        subscribers[type].push_back(callback);
    }

    void RunDispatcher() {
        isRunning = true;
        dispatcherThread = std::thread([this]() {
            while (isRunning) {
                Event currentEvent;
                {
                    std::unique_lock<std::mutex> lock(queueMutex);
                    queueCondition.wait(lock, [this] {
                        return !eventQueue.empty() || !isRunning;
                        });

                    if (!isRunning && eventQueue.empty()) break;

                    currentEvent = eventQueue.front();
                    eventQueue.pop();
                }

                if (currentEvent.type == EventType::SHUTDOWN_REQUESTED) {
                    isRunning = false;
                    break;
                }

                Dispatch(currentEvent);
            }
            });
    }

    void Stop() {
        if (isRunning) {
            Publish({ EventType::SHUTDOWN_REQUESTED, std::monostate{} });
        }
        if (dispatcherThread.joinable()) {
            dispatcherThread.join();
        }
    }

private:
    void Dispatch(const Event& event) {
        auto it = subscribers.find(event.type);
        if (it != subscribers.end()) {
            for (const auto& callback : it->second) {
                callback(event);
            }
        }
    }

    std::queue<Event> eventQueue;
    std::mutex queueMutex;
    std::condition_variable queueCondition;
    std::unordered_map<EventType, std::vector<SubscriberCallback>> subscribers;
    std::atomic<bool> isRunning{ false };
    std::thread dispatcherThread;
};