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
    // unique_ptr gives the store sole ownership of each Message and ensures it is
    // deleted automatically when removed or when the store goes out of scope.
    // Methods that return pointers give back raw non-owning pointers so callers
    // can read the data without accidentally taking ownership.
    std::vector<std::unique_ptr<Message>> m_messages;
};
