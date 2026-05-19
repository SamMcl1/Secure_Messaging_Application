#pragma once
#include <string>
#include <ctime>

class Message {
public:
    Message(std::string id,
            std::string sender,
            std::string recipient,
            std::string ciphertext,
            std::time_t timestamp);

    const std::string& getId()         const;
    const std::string& getSender()     const;
    const std::string& getRecipient()  const;
    const std::string& getCiphertext() const;
    std::time_t        getTimestamp()  const;

private:
    std::string m_id;
    std::string m_sender;
    std::string m_recipient;
    std::string m_ciphertext;
    std::time_t m_timestamp;
};
