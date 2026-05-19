# C++ Secure Messaging Client

Command-line client for the Secure Messaging Application.  
Communicates with the Python backend over HTTPS using **libcurl** and parses JSON responses with **nlohmann/json**.

---

## Dependencies

| Dependency | How it is obtained |
|---|---|
| C++17 compiler (g++ ≥ 9 or clang++ ≥ 10 or MSVC 2019+) | System package manager |
| CMake ≥ 3.16 | System package manager |
| libcurl (with SSL support) | System package manager |
| nlohmann/json v3.11.3 | Downloaded automatically by CMake at configure time |

### Install system dependencies

**Ubuntu / Debian (Linux VM)**
```bash
sudo apt update
sudo apt install -y build-essential cmake libcurl4-openssl-dev
```

**macOS (Homebrew)**
```bash
brew install cmake curl
```

**Windows (vcpkg)**
```powershell
vcpkg install curl:x64-windows
# then pass -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake to cmake
```

---

## Building

```bash
# 1. From the repo root, navigate to the C++ client directory
cd client/cpp

# 2. Create a build directory (keeps source tree clean)
mkdir build && cd build

# 3. Configure — CMake downloads nlohmann/json automatically here
cmake ..

# 4. Compile
cmake --build . --config Release

# The binary is produced at:  build/secure_client  (Linux/macOS)
#                              build/Release/secure_client.exe  (Windows)
```

> **Offline builds:** If the build machine has no internet access, download
> `json.hpp` from the nlohmann/json v3.11.3 release, place it in
> `client/cpp/include/`, and replace the `FetchContent` block in
> `CMakeLists.txt` with just the `target_include_directories` line pointing
> to `include/`.

---

## Running

```bash
./build/secure_client
```

---

## Project structure

```
client/cpp/
├── CMakeLists.txt        — build configuration
├── README.md             — this file
├── include/              — header files (.h / .hpp)
└── src/
    └── main.cpp          — entry point
```

---

## Class overview

| Class | File | Responsibility |
|---|---|---|
| `Client` | `include/Client.hpp` / `src/Client.cpp` | HTTPS connection to backend, auth token management |
| `Message` | `include/Message.hpp` / `src/Message.cpp` | Holds sender, recipient, ciphertext, timestamp, tx hash |
| `MessageStore` | `include/MessageStore.hpp` / `src/MessageStore.cpp` | Local in-memory store of messages (std::vector) |
| `User` | `include/User.hpp` / `src/User.cpp` | Logged-in user identity and public/private key handles |

---

## Notes

- libcurl is used for all HTTPS requests; SSL certificate verification is **enabled** (default).  
  `CURLOPT_SSL_VERIFYPEER` and `CURLOPT_SSL_VERIFYHOST` are never disabled.
- nlohmann/json is header-only; no separate compilation step is needed for it.
