#include "Conversation.hpp"
#include <algorithm>

std::string Conversation::makeKey(const std::string& a, const std::string& b) {
    return (a < b) ? a + "|" + b : b + "|" + a;
}

void Conversation::addMessage(std::unique_ptr<Message> message) {
    if (!message) return;
    auto key = makeKey(message->getSender(), message->getRecipient());
    m_threads[key].push_back(std::move(message));
}

std::vector<const Message*> Conversation::getThread(const std::string& userA,
                                                     const std::string& userB) const {
    auto it = m_threads.find(makeKey(userA, userB));
    if (it == m_threads.end()) return {};

    std::vector<const Message*> result;
    result.reserve(it->second.size());
    for (const auto& msg : it->second) {
        result.push_back(msg.get());
    }

    std::sort(result.begin(), result.end(), [](const Message* a, const Message* b) {
        return a->getTimestamp() < b->getTimestamp();
    });

    return result;
}

std::size_t Conversation::messageCount(const std::string& userA,
                                        const std::string& userB) const {
    auto it = m_threads.find(makeKey(userA, userB));
    return it == m_threads.end() ? 0 : it->second.size();
}

const Message* Conversation::findLatest(const std::string& userA,
                                         const std::string& userB) const {
    auto it = m_threads.find(makeKey(userA, userB));
    if (it == m_threads.end() || it->second.empty()) return nullptr;

    auto maxIt = std::max_element(
        it->second.begin(), it->second.end(),
        [](const std::unique_ptr<Message>& a, const std::unique_ptr<Message>& b) {
            return a->getTimestamp() < b->getTimestamp();
        });

    return maxIt->get();
}

std::size_t Conversation::totalCount() const {
    std::size_t total = 0;
    for (const auto& [key, vec] : m_threads) {
        total += vec.size();
    }
    return total;
}
