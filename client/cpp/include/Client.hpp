#pragma once
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "MessageStore.hpp"

// HTTP client that talks to the Flask backend over HTTPS.
// All auth tokens are kept in memory — never written to disk.
class Client {
public:
    explicit Client(std::string baseUrl, std::string certPin = "");

    // POST /auth/login — stores access/refresh tokens on success.
    bool login(const std::string& username, const std::string& password);

    // POST /messages/ — ciphertext and ephPub must be base64-encoded.
    bool sendMessage(int recipientId,
                     const std::string& ciphertext,
                     const std::string& ephPub);

    // GET /messages/ — deserialises the response into Message objects and
    // appends them to store. Returns the number of messages added, or -1 on
    // HTTP error, or -2 on JSON parse error.
    int fetchInbox(MessageStore& store);

    // GET /messages/ — returns raw JSON for callers that need to decrypt
    // ciphertext before constructing Message objects.
    std::vector<nlohmann::json> getMessages();

    bool isLoggedIn() const;
    int  getUserId()  const;

private:
    struct Response {
        long        status{0};
        std::string body;
    };

    Response httpPost(const std::string& path, const std::string& jsonBody);
    Response httpGet (const std::string& path);

    std::string m_baseUrl;
    std::string m_certPin;
    std::string m_accessToken;
    std::string m_refreshToken;
    int         m_userId{0};
};
