#include "Message.hpp"
#include <utility>

Message::Message(std::string id,
                 std::string sender,
                 std::string recipient,
                 std::string ciphertext,
                 std::time_t timestamp)
    : m_id(std::move(id))
    , m_sender(std::move(sender))
    , m_recipient(std::move(recipient))
    , m_ciphertext(std::move(ciphertext))
    , m_timestamp(timestamp)
{}

const std::string& Message::getId()         const { return m_id; }
const std::string& Message::getSender()     const { return m_sender; }
const std::string& Message::getRecipient()  const { return m_recipient; }
const std::string& Message::getCiphertext() const { return m_ciphertext; }
std::time_t        Message::getTimestamp()  const { return m_timestamp; }
