cmake_minimum_required(VERSION 3.16)
project(SecureMessagingClient CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ---------- compiler warnings ----------
if(MSVC)
    add_compile_options(/W4 /WX)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

# ---------- libcurl ----------
find_package(CURL REQUIRED)

# ---------- nlohmann/json (single-header, downloaded at configure time) ----------
# Downloads json.hpp into _deps/nlohmann/nlohmann/ so the canonical
# #include <nlohmann/json.hpp> works without any additional setup.
#
# The SHA-256 is re-checked on every configure run. If the cached file is
# missing or its hash no longer matches (tampered or corrupted), it is
# removed and re-downloaded so the integrity guarantee always holds.
set(_NLOHMANN_ROOT   "${CMAKE_BINARY_DIR}/_deps/nlohmann")
set(_NLOHMANN_HEADER "${_NLOHMANN_ROOT}/nlohmann/json.hpp")
set(_NLOHMANN_HASH   "9bea4c8066ef4a1c206b2be5a36302f8926f7fdc6087af5d20b417d0cf103ea6")

if(EXISTS "${_NLOHMANN_HEADER}")
    file(SHA256 "${_NLOHMANN_HEADER}" _NLOHMANN_ACTUAL_HASH)
    if(NOT _NLOHMANN_ACTUAL_HASH STREQUAL _NLOHMANN_HASH)
        message(WARNING "nlohmann/json hash mismatch — re-downloading")
        file(REMOVE "${_NLOHMANN_HEADER}")
    endif()
endif()

if(NOT EXISTS "${_NLOHMANN_HEADER}")
    file(MAKE_DIRECTORY "${_NLOHMANN_ROOT}/nlohmann")
    file(DOWNLOAD
        "https://github.com/nlohmann/json/releases/download/v3.11.3/json.hpp"
        "${_NLOHMANN_HEADER}"
        EXPECTED_HASH SHA256=${_NLOHMANN_HASH}
        SHOW_PROGRESS
    )
endif()

add_library(nlohmann_json_iface INTERFACE)
target_include_directories(nlohmann_json_iface INTERFACE "${_NLOHMANN_ROOT}")

# ---------- sources ----------
file(GLOB_RECURSE SOURCES "src/*.cpp")

add_executable(secure_client ${SOURCES})

target_include_directories(secure_client PRIVATE include)

target_link_libraries(secure_client
    PRIVATE
        CURL::libcurl
        nlohmann_json_iface
)
