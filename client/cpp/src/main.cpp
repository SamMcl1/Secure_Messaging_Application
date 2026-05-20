#include <iostream>
#include <string>
#include "Client.hpp"

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: secure_client <base_url> <username> <password>\n"
                  << "  e.g. secure_client https://hangover.theburkenator.com alice mypassword\n";
        return 1;
    }

    const std::string baseUrl  = argv[1];
    const std::string username = argv[2];
    const std::string password = argv[3];

    Client client(baseUrl);

    if (!client.login(username, password)) {
        std::cerr << "Login failed\n";
        return 1;
    }

    std::cout << "Logged in (user_id=" << client.getUserId() << ")\n";

    auto messages = client.getMessages();
    std::cout << "Inbox: " << messages.size() << " message(s)\n";

    return 0;
}
