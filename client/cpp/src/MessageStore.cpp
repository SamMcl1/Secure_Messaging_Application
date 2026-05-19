#include "MessageStore.hpp"
#include <algorithm>

void MessageStore::add(std::unique_ptr<Message> message) {
    m_messages.push_back(std::move(message));
}

bool MessageStore::remove(const std::string& id) {
    // erase-remove idiom: std::remove_if shuffles matching elements to the end,
    // then erase deletes them. Returns true if anything was actually removed.
    auto before = m_messages.size();
    m_messages.erase(
        std::remove_if(m_messages.begin(), m_messages.end(),
            [&id](const std::unique_ptr<Message>& m) {
                return m->getId() == id;
            }),
        m_messages.end()
    );
    return m_messages.size() < before;
}

const Message* MessageStore::findById(const std::string& id) const {
    auto it = std::find_if(m_messages.begin(), m_messages.end(),
        [&id](const std::unique_ptr<Message>& m) {
            return m->getId() == id;
        });
    return (it != m_messages.end()) ? it->get() : nullptr;
}

std::vector<const Message*> MessageStore::findBySender(const std::string& sender) const {
    std::vector<const Message*> results;
    for (const auto& m : m_messages) {
        if (m->getSender() == sender) {
            results.push_back(m.get());
        }
    }
    return results;
}

std::vector<const Message*> MessageStore::getSortedByTime() const {
    std::vector<const Message*> ptrs;
    ptrs.reserve(m_messages.size());
    for (const auto& m : m_messages) {
        ptrs.push_back(m.get());
    }
    std::sort(ptrs.begin(), ptrs.end(),
        [](const Message* a, const Message* b) {
            return a->getTimestamp() < b->getTimestamp();
        });
    return ptrs;
}

std::size_t MessageStore::size() const {
    return m_messages.size();
}
