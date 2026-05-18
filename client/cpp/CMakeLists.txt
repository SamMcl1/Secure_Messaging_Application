cmake_minimum_required(VERSION 3.16)
project(SecureMessagingClient CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

file(GLOB_RECURSE SOURCES "src/*.cpp")

add_executable(secure_client ${SOURCES})

target_include_directories(secure_client PRIVATE include)

# Uncomment once the C++ component role is decided:
# find_package(OpenSSL REQUIRED)
# target_link_libraries(secure_client OpenSSL::SSL OpenSSL::Crypto)
