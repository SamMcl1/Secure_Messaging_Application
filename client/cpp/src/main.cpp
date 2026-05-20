#include <iostream>
#include "Client.hpp"

int main() {
    Client client("https://hangover.theburkenator.com");

    if (!client.login("alice", "password123")) {
        std::cerr << "Login failed\n";
        return 1;
    }

    std::cout << "Logged in (user_id=" << client.getUserId() << ")\n";

    auto messages = client.getMessages();
    std::cout << "Inbox: " << messages.size() << " message(s)\n";

    return 0;
}
