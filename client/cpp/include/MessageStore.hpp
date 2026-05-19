#pragma once
#include "Message.hpp"
#include <memory>
#include <string>
#include <vector>

class MessageStore {
public:
    void add(std::unique_ptr<Message> message);

    // Returns true if a message with that id was found and removed.
    bool remove(const std::string& id);

    // Returns an observing pointer, or nullptr if not found.
    const Message* findById(const std::string& id) const;

    // Returns observing pointers to every message from that sender.
    std::vector<const Message*> findBySender(const std::string& sender) const;

    // Returns observing pointers to all messages sorted by timestamp (ascending).
    std::vector<const Message*> getSortedByTime() const;

    std::size_t size() const;

private:
    std::vector<std::unique_ptr<Message>> m_messages;
};
