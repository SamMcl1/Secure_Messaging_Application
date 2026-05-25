#include <ctime>
#include <iomanip>
#include <iostream>
#include <limits>
#include <string>
#include "Client.hpp"
#include "MessageStore.hpp"

static void printMessage(const Message* m) {
    std::time_t ts = m->getTimestamp();
    char timeBuf[32] = "unknown";
    if (ts != 0) {
        if (auto* tm = std::localtime(&ts))
            std::strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", tm);
    }

    const auto& ct = m->getCiphertext();
    std::string preview = ct.size() > 48 ? ct.substr(0, 48) + "..." : ct;

    std::cout << "[" << timeBuf << "] #" << m->getId()
              << "  " << m->getSender() << " -> " << m->getRecipient() << "\n"
              << "  ciphertext: " << preview << "\n";
}

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
        std::cerr << "Login failed — check credentials and server URL\n";
        return 1;
    }
    std::cout << "Logged in as " << username
              << " (user_id=" << client.getUserId() << ")\n";

    MessageStore store;
    std::string cmd;

    while (true) {
        std::cout << "\nCommands: send | inbox | quit\n> ";
        if (!(std::cin >> cmd)) break;

        if (cmd == "quit" || cmd == "q") {
            std::cout << "Goodbye.\n";
            break;
        }

        if (cmd == "inbox") {
            store = MessageStore{};
            int n = client.fetchInbox(store);
            if (n == -1) {
                std::cerr << "Failed to fetch messages (server error)\n";
                continue;
            }
            if (n == -2) {
                std::cerr << "Failed to fetch messages (malformed response)\n";
                continue;
            }
            if (n == 0) {
                std::cout << "No messages.\n";
                continue;
            }
            std::cout << n << " message(s)\n";
            for (const auto* m : store.getSortedByTime()) {
                printMessage(m);
            }
            continue;
        }

        if (cmd == "send") {
            int recipientId = 0;
            std::cout << "Recipient user ID: ";
            if (!(std::cin >> recipientId) || recipientId <= 0) {
                std::cin.clear();
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                std::cerr << "Invalid recipient ID\n";
                continue;
            }
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

            std::string ciphertext, ephPub;
            std::cout << "Ciphertext (base64): ";
            std::getline(std::cin, ciphertext);

            std::cout << "Ephemeral public key (base64, eph_pub): ";
            std::getline(std::cin, ephPub);

            if (ciphertext.empty() || ephPub.empty()) {
                std::cerr << "Ciphertext and eph_pub must not be empty\n";
                continue;
            }

            if (client.sendMessage(recipientId, ciphertext, ephPub)) {
                std::cout << "Message sent.\n";
            } else {
                std::cerr << "Failed to send — check recipient ID and that "
                             "ciphertext/eph_pub are valid base64\n";
            }
            continue;
        }

        std::cerr << "Unknown command. Try: send | inbox | quit\n";
    }

    return 0;
}
