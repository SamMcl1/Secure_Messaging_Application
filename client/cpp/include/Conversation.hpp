#pragma once
#include "Message.hpp"
#include <cstddef>
#include <map>
#include <memory>
#include <string>
#include <vector>

// Groups Message objects by participant pair.
// A thread between Alice and Bob is keyed the same regardless of who sent each
// message — the canonical key sorts the two usernames so "alice|bob" == "bob|alice".
class Conversation {
public:
    // Takes ownership of the message and files it under the correct thread.
    void addMessage(std::unique_ptr<Message> message);

    // Returns observing pointers to all messages in the thread between userA
    // and userB, sorted by timestamp ascending. Returns empty if no thread exists.
    std::vector<const Message*> getThread(const std::string& userA,
                                          const std::string& userB) const;

    // Number of messages exchanged between userA and userB.
    std::size_t messageCount(const std::string& userA,
                             const std::string& userB) const;

    // Observing pointer to the most recent message between userA and userB.
    // Returns nullptr if the thread does not exist or is empty.
    const Message* findLatest(const std::string& userA,
                              const std::string& userB) const;

    // Total messages across all threads.
    std::size_t totalCount() const;

private:
    // Produces a canonical key: the lexicographically smaller username first,
    // separated by '|'. Ensures alice->bob and bob->alice share one thread.
    static std::string makeKey(const std::string& a, const std::string& b);

    std::map<std::string, std::vector<std::unique_ptr<Message>>> m_threads;
};
