cmake_minimum_required(VERSION 3.16)
project(SecureMessagingClient CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---------- compiler warnings ----------
if(MSVC)
    add_compile_options(/W4 /WX)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

# ---------- libcurl ----------
find_package(CURL REQUIRED)

# ---------- nlohmann/json (header-only, fetched at configure time) ----------
include(FetchContent)
FetchContent_Declare(
    nlohmann_json
    URL      https://github.com/nlohmann/json/releases/download/v3.11.3/json.hpp
    URL_HASH SHA256=9bea4c8066ef4a1c206b2be5a36302f8926f7fdc6087af5d20b417d0cf103ea6
    DOWNLOAD_NO_EXTRACT TRUE
    SOURCE_DIR "${CMAKE_BINARY_DIR}/_deps/nlohmann"
)
FetchContent_MakeAvailable(nlohmann_json)

# Expose as an interface target so we can link it like a proper library
add_library(nlohmann_json_iface INTERFACE)
target_include_directories(nlohmann_json_iface INTERFACE
    "${CMAKE_BINARY_DIR}/_deps/nlohmann"
)

# ---------- sources ----------
file(GLOB_RECURSE SOURCES "src/*.cpp")

add_executable(secure_client ${SOURCES})

target_include_directories(secure_client PRIVATE include)

target_link_libraries(secure_client
    PRIVATE
        CURL::libcurl
        nlohmann_json_iface
)
