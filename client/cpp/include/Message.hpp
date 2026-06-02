#pragma once
#include <string>
#include <ctime>

// Represents a single encrypted message, either received from the server or ready to send.
// The server stores and relays only ciphertext, so the plaintext never touches it.
// ephPub is the sender's ephemeral public key; the recipient needs it alongside their
// own private key to re-derive the shared secret and decrypt the ciphertext.
class Message {
public:
    Message(std::string id,
            std::string sender,
            std::string recipient,
            std::string ciphertext,
            std::string ephPub,
            std::time_t timestamp);

    const std::string& getId()         const;
    const std::string& getSender()     const;
    const std::string& getRecipient()  const;
    const std::string& getCiphertext() const;
    const std::string& getEphPub()     const;
    std::time_t        getTimestamp()  const;

private:
    std::string m_id;
    std::string m_sender;
    std::string m_recipient;
    std::string m_ciphertext;
    std::string m_ephPub;
    std::time_t m_timestamp;
};
