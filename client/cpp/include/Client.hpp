#pragma once
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

// HTTP client that talks to the Flask backend over HTTPS.
// All auth tokens are kept in memory — never written to disk.
class Client {
public:
    explicit Client(std::string baseUrl);

    // POST /auth/login — stores access/refresh tokens on success.
    bool login(const std::string& username, const std::string& password);

    // POST /messages/ — ciphertext and nonce must be base64-encoded.
    bool sendMessage(int recipientId,
                     const std::string& ciphertext,
                     const std::string& nonce);

    // GET /messages/ — returns raw JSON objects for the caller to decrypt.
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
    std::string m_accessToken;
    std::string m_refreshToken;
    int         m_userId{0};
};
