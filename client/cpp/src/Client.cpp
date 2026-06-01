#include "Client.hpp"
#include <curl/curl.h>
#include <iomanip>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>

using json = nlohmann::json;

// ---------------------------------------------------------------------------
// Internal helpers (not exposed in the header)
// ---------------------------------------------------------------------------

// Collect libcurl response bytes into a std::string.
static size_t writeCallback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* buf = static_cast<std::string*>(userdata);
    buf->append(ptr, size * nmemb);
    return size * nmemb;
}

// RAII wrapper for curl_slist so headers are always freed.
struct SlistDeleter {
    void operator()(curl_slist* p) const { curl_slist_free_all(p); }
};
using SlistPtr = std::unique_ptr<curl_slist, SlistDeleter>;

// Create a CURL handle wrapped in a unique_ptr.
// curl_easy_cleanup is the deleter, so the handle is freed automatically
// when the unique_ptr goes out of scope — even on early returns.
static std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> makeCurl(const std::string& pin) {
    CURL* raw = curl_easy_init();
    if (!raw) throw std::runtime_error("curl_easy_init failed");

    std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> handle(raw, curl_easy_cleanup);

    // Always verify the server's SSL certificate and hostname.
    curl_easy_setopt(handle.get(), CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(handle.get(), CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(handle.get(), CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(handle.get(), CURLOPT_WRITEFUNCTION, writeCallback);

    // If a pin is set, reject any cert whose public key doesn't match — even
    // a CA-valid cert. Format: "sha256//<base64-encoded-spki-hash>".
    if (!pin.empty()) {
        const CURLcode rc =
            curl_easy_setopt(handle.get(), CURLOPT_PINNEDPUBLICKEY, pin.c_str());
        if (rc != CURLE_OK)
            throw std::runtime_error(std::string("Failed to set pinned public key: ") +
                                     curl_easy_strerror(rc));
    }

    return handle;
}

// ---------------------------------------------------------------------------
// Client implementation
// ---------------------------------------------------------------------------

Client::Client(std::string baseUrl, std::string certPin)
    : m_baseUrl(std::move(baseUrl)), m_certPin(std::move(certPin))
{
    // curl_global_init must be called once per process before any easy handle
    // is created. The static flag ensures this happens exactly once even if
    // multiple Client instances are constructed. std::atexit registers the
    // matching cleanup so resources are released at process exit.
    static std::once_flag initFlag;
    std::call_once(initFlag, []() {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        std::atexit(curl_global_cleanup);
    });
}

Client::Response Client::httpPost(const std::string& path, const std::string& jsonBody) {
    auto curl = makeCurl(m_certPin);
    Response resp;

    curl_easy_setopt(curl.get(), CURLOPT_URL,        (m_baseUrl + path).c_str());
    curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA,  &resp.body);
    curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, jsonBody.c_str());

    // Build header list; wrap immediately in SlistPtr for automatic cleanup.
    curl_slist* raw = nullptr;
    raw = curl_slist_append(raw, "Content-Type: application/json");
    if (!m_accessToken.empty())
        raw = curl_slist_append(raw, ("Authorization: Bearer " + m_accessToken).c_str());
    SlistPtr headers(raw);
    curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, headers.get());

    if (curl_easy_perform(curl.get()) == CURLE_OK)
        curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &resp.status);

    return resp;
}

Client::Response Client::httpGet(const std::string& path) {
    auto curl = makeCurl(m_certPin);
    Response resp;

    curl_easy_setopt(curl.get(), CURLOPT_URL,       (m_baseUrl + path).c_str());
    curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &resp.body);
    curl_easy_setopt(curl.get(), CURLOPT_HTTPGET,   1L);

    // Attach the auth header only when a token is present, but always
    // perform the request so callers receive the real HTTP status (e.g. 401).
    SlistPtr headers;
    if (!m_accessToken.empty()) {
        headers.reset(curl_slist_append(nullptr,
            ("Authorization: Bearer " + m_accessToken).c_str()));
        curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, headers.get());
    }

    if (curl_easy_perform(curl.get()) == CURLE_OK)
        curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &resp.status);

    return resp;
}

bool Client::login(const std::string& username, const std::string& password) {
    // Clear any stale credentials first so isLoggedIn() never reflects a
    // previous successful login after a failed re-login attempt.
    m_accessToken.clear();
    m_refreshToken.clear();
    m_userId = 0;

    const std::string body = json{{"username", username}, {"password", password}}.dump();
    auto resp = httpPost("/auth/login", body);
    if (resp.status != 200) return false;

    try {
        auto j          = json::parse(resp.body);
        m_accessToken   = j.at("access_token").get<std::string>();
        m_refreshToken  = j.at("refresh_token").get<std::string>();
        m_userId        = j.at("user_id").get<int>();
        return true;
    } catch (...) {
        m_accessToken.clear();
        m_refreshToken.clear();
        m_userId = 0;
        return false;
    }
}

bool Client::sendMessage(int recipientId,
                         const std::string& ciphertext,
                         const std::string& ephPub) {
    const std::string body = json{
        {"recipient_id", recipientId},
        {"ciphertext",   ciphertext},
        {"eph_pub",      ephPub}
    }.dump();
    auto resp = httpPost("/messages/", body);
    if (resp.status != 201) return false;
    return true;
}

std::vector<nlohmann::json> Client::getMessages() {
    auto resp = httpGet("/messages/");
    if (resp.status != 200) return {};

    try {
        return json::parse(resp.body).get<std::vector<json>>();
    } catch (...) {
        return {};
    }
}

int Client::fetchInbox(MessageStore& store) {
    auto resp = httpGet("/messages/");
    if (resp.status != 200) return -1;

    try {
        auto arr = json::parse(resp.body);
        int count = 0;
        for (const auto& j : arr) {
            // BIGSERIAL in Postgres can exceed 32-bit int; use long long.
            std::string id        = std::to_string(j.at("id").get<long long>());
            std::string sender    = j.at("sender_username").get<std::string>();
            std::string recipient = j.at("recipient_username").get<std::string>();
            std::string ciphertext = j.at("ciphertext").get<std::string>();
            std::string ephPub    = j.at("eph_pub").get<std::string>();

            // Flask jsonify serialises datetimes as RFC 1123 on older versions
            // ("Sun, 25 May 2026 11:42:12 GMT") and ISO 8601 on newer ones
            // ("2026-05-25T11:42:12"). Try ISO 8601 first, fall back to RFC 1123.
            std::time_t ts = 0;
            auto it = j.find("created_at");
            if (it != j.end() && it->is_string()) {
                const std::string& tsStr = it->get<std::string>();
                std::tm tm{};
                std::istringstream ss(tsStr);
                ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
                if (ss.fail()) {
                    ss.clear();
                    ss.str(tsStr);
                    ss >> std::get_time(&tm, "%a, %d %b %Y %H:%M:%S");
                }
                if (!ss.fail()) ts = std::mktime(&tm);
            }

            store.add(std::make_unique<Message>(
                std::move(id), std::move(sender), std::move(recipient),
                std::move(ciphertext), std::move(ephPub), ts));
            ++count;
        }
        return count;
    } catch (...) {
        return -2;
    }
}

bool Client::isLoggedIn() const { return !m_accessToken.empty(); }
int  Client::getUserId()  const { return m_userId; }
