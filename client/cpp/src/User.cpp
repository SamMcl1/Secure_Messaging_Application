#include "User.hpp"
#include <utility>

// std::move transfers the strings from the constructor parameters into the members
// rather than copying them. The parameters are already local copies, so moving is free.
User::User(std::string id, std::string username, std::string publicKey)
    : m_id(std::move(id))
    , m_username(std::move(username))
    , m_publicKey(std::move(publicKey))
{}

const std::string& User::getId()        const { return m_id; }
const std::string& User::getUsername()  const { return m_username; }
const std::string& User::getPublicKey() const { return m_publicKey; }
