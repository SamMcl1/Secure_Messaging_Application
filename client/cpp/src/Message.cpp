#include "Message.hpp"
#include <utility>

// Move the string parameters into the members instead of copying them.
// The timestamp is a plain integer (time_t) so it gets copied by value as normal.
Message::Message(std::string id,
                 std::string sender,
                 std::string recipient,
                 std::string ciphertext,
                 std::string ephPub,
                 std::time_t timestamp)
    : m_id(std::move(id))
    , m_sender(std::move(sender))
    , m_recipient(std::move(recipient))
    , m_ciphertext(std::move(ciphertext))
    , m_ephPub(std::move(ephPub))
    , m_timestamp(timestamp)
{}

const std::string& Message::getId()         const { return m_id; }
const std::string& Message::getSender()     const { return m_sender; }
const std::string& Message::getRecipient()  const { return m_recipient; }
const std::string& Message::getCiphertext() const { return m_ciphertext; }
const std::string& Message::getEphPub()     const { return m_ephPub; }
std::time_t        Message::getTimestamp()  const { return m_timestamp; }
