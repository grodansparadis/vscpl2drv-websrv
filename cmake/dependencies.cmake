# dependencies.cmake
#
# Third-party sources, fetched at configure time with FetchContent. They used
# to be git submodules in third_party/; each is pinned to the same commit.
# Every download is checked against its SHA256.
#
# To use a local checkout instead, set FETCHCONTENT_SOURCE_DIR_<NAME>, for
# example -DFETCHCONTENT_SOURCE_DIR_TP_CIVETWEB=/path/to/civetweb.
# FETCHCONTENT_FULLY_DISCONNECTED=ON reuses downloaded sources offline.
#
# Sets:
#   THIRD_PARTY_CIVETWEB_DIR           civetweb/civetweb
#   THIRD_PARTY_VSCP_DIR               grodansparadis/vscp
#   THIRD_PARTY_SPDLOG_DIR             gabime/spdlog
#   THIRD_PARTY_JSON_DIR               nlohmann/json
#   THIRD_PARTY_MUSTACHE_DIR           kainjow/Mustache
#   THIRD_PARTY_LUA_DIR                Lua 5.3.5 (lua.org release)
#   THIRD_PARTY_DUKTAPE_DIR            duktape 2.7.0 (GitHub release)
#   THIRD_PARTY_SQLITE3_DIR            SQLite 3.50.4 amalgamation
#

include_guard(GLOBAL)
include(FetchContent)

set(_tp_options)
if(NOT CMAKE_VERSION VERSION_LESS "3.18")
    # Populate the sources only; the projects are not added to the build.
    list(APPEND _tp_options SOURCE_SUBDIR "__sources_only__")
endif()
if(NOT CMAKE_VERSION VERSION_LESS "3.24")
    list(APPEND _tp_options DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
endif()

# civetweb/civetweb @ dfdfdb6926765541751cab055472f70daa9aa2dd
FetchContent_Declare(
    tp_civetweb
    URL https://codeload.github.com/civetweb/civetweb/tar.gz/dfdfdb6926765541751cab055472f70daa9aa2dd
    URL_HASH SHA256=7efc8e5da16b9af4fa8197822c49fe276f714041161c17b62b211ad61eb08bc5
    ${_tp_options}
)
# grodansparadis/vscp @ 8a3218b3e5a7eb1cf6bcc57fd7739f190d13b3a6
FetchContent_Declare(
    tp_vscp
    URL https://codeload.github.com/grodansparadis/vscp/tar.gz/8a3218b3e5a7eb1cf6bcc57fd7739f190d13b3a6
    URL_HASH SHA256=cc032559604672b8f915db9b7ce5d39959a2d00964fbfe180baf3ea7abbbb34f
    ${_tp_options}
)
# gabime/spdlog @ 486b55554f11c9cccc913e11a87085b2a91f706f
FetchContent_Declare(
    tp_spdlog
    URL https://codeload.github.com/gabime/spdlog/tar.gz/486b55554f11c9cccc913e11a87085b2a91f706f
    URL_HASH SHA256=d2fef585c9879dd239dc498e2e8a1e22982b3ed67b2d14e78622b7ef25bdfdfa
    ${_tp_options}
)
# nlohmann/json @ 0d69a721676dedd9d1a4f514b58145a44a349bc4
FetchContent_Declare(
    tp_json
    URL https://codeload.github.com/nlohmann/json/tar.gz/0d69a721676dedd9d1a4f514b58145a44a349bc4
    URL_HASH SHA256=7f0a9021b0567190b3c5368a6dc86b13f6f18809aa891c4bac9d0671bc807151
    ${_tp_options}
)
# kainjow/Mustache @ 3f654942a70c46a775070d7a09ca7acfa3e205b7
FetchContent_Declare(
    tp_mustache
    URL https://codeload.github.com/kainjow/Mustache/tar.gz/3f654942a70c46a775070d7a09ca7acfa3e205b7
    URL_HASH SHA256=959b8fcaecc14fc0b6243c078a39fd13dab107dcda086ed2ca90e1a486269a36
    ${_tp_options}
)

# Lua, duktape and SQLite releases (these used to be copied into third_party/).
# Lua is unpacked into a folder named lua-5.3.5 because third_party/lua_all.c
# includes its sources as "lua-5.3.5/src/<file>.c".
FetchContent_Declare(
    tp_lua
    # lua.org first, then the official mirror (tried in order)
    URL https://www.lua.org/ftp/lua-5.3.5.tar.gz
        https://www.tecgraf.puc-rio.br/lua/ftp/lua-5.3.5.tar.gz
    URL_HASH SHA256=0c2eed3f960446e1a3e4b9a1ca2f3ff893b6ce41942cf54d5dd59ab4b3b058ac
    SOURCE_DIR ${FETCHCONTENT_BASE_DIR}/lua/lua-5.3.5
    ${_tp_options}
)
FetchContent_Declare(
    tp_duktape
    URL https://github.com/svaarala/duktape/releases/download/v2.7.0/duktape-2.7.0.tar.xz
    URL_HASH SHA256=90f8d2fa8b5567c6899830ddef2c03f3c27960b11aca222fa17aa7ac613c2890
    ${_tp_options}
)
FetchContent_Declare(
    tp_sqlite3
    URL https://www.sqlite.org/2025/sqlite-amalgamation-3500400.zip
    URL_HASH SHA256=1d3049dd0f830a025a53105fc79fd2ab9431aea99e137809d064d8ee8356b032
    ${_tp_options}
)

set(_tp_names tp_civetweb tp_vscp tp_spdlog tp_json tp_mustache tp_lua tp_duktape tp_sqlite3)
if(CMAKE_VERSION VERSION_LESS "3.18")
    foreach(_tp IN LISTS _tp_names)
        FetchContent_GetProperties(${_tp})
        if(NOT ${_tp}_POPULATED)
            FetchContent_Populate(${_tp})
        endif()
    endforeach()
else()
    FetchContent_MakeAvailable(${_tp_names})
endif()

set(THIRD_PARTY_CIVETWEB_DIR "${tp_civetweb_SOURCE_DIR}")
set(THIRD_PARTY_VSCP_DIR "${tp_vscp_SOURCE_DIR}")
set(THIRD_PARTY_SPDLOG_DIR "${tp_spdlog_SOURCE_DIR}")
set(THIRD_PARTY_JSON_DIR "${tp_json_SOURCE_DIR}")
set(THIRD_PARTY_MUSTACHE_DIR "${tp_mustache_SOURCE_DIR}")
set(THIRD_PARTY_LUA_DIR "${tp_lua_SOURCE_DIR}")
get_filename_component(THIRD_PARTY_LUA_PARENT_DIR "${tp_lua_SOURCE_DIR}" DIRECTORY)
set(THIRD_PARTY_DUKTAPE_DIR "${tp_duktape_SOURCE_DIR}")
set(THIRD_PARTY_SQLITE3_DIR "${tp_sqlite3_SOURCE_DIR}")
