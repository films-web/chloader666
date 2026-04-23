#pragma once
#include <string>
#include <functional>
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Bcrypt.lib")
#include <ixwebsocket/IXNetSystem.h>
#include <ixwebsocket/IXWebSocket.h>

class NetworkClient {
public:
    using MessageCallback = std::function<void(const std::string&)>;
    using StatusCallback = std::function<void(bool, const std::string&)>;

    NetworkClient() {
        static bool netInitialized = false;
        if (!netInitialized) {
            ix::initNetSystem();
            netInitialized = true;
        }
    }

    ~NetworkClient() { Stop(); }

    void Start(const std::string& url, StatusCallback onStatus, MessageCallback onMessage) {
        m_webSocket.setUrl(url);
        m_webSocket.enableAutomaticReconnection();
        m_webSocket.setMaxWaitBetweenReconnectionRetries(5000);
        m_webSocket.setPingInterval(45);

        m_webSocket.setOnMessageCallback([onStatus, onMessage](const ix::WebSocketMessagePtr& msg) {
            if (msg->type == ix::WebSocketMessageType::Open) {
                onStatus(true, "");
            }
            else if (msg->type == ix::WebSocketMessageType::Close) {
                onStatus(false, "Disconnected by server");
            }
            else if (msg->type == ix::WebSocketMessageType::Error) {
                onStatus(false, msg->errorInfo.reason);
            }
            else if (msg->type == ix::WebSocketMessageType::Message) {
                onMessage(msg->str);
            }
            });
        m_webSocket.start();
    }

    void Send(const std::string& msg) { m_webSocket.send(msg); }
    void Stop() { m_webSocket.stop(); }

private:
    ix::WebSocket m_webSocket;
};