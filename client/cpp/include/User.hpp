#pragma once
#include <string>

// User holds the basic info the client needs about a registered account.
// The server keeps full account details; we only store the id, username,
// and public key so we can address and encrypt messages to this person.
class User {
public:
    User(std::string id, std::string username, std::string publicKey);

    const std::string& getId()        const;
    const std::string& getUsername()  const;
    const std::string& getPublicKey() const;

private:
    std::string m_id;
    std::string m_username;
    std::string m_publicKey;
};
