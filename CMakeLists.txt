# CMakeLists.txt
#
# Build instructions for VSCP Works.
#
# Copyright (c) 2000-2025 Åke Hedman, the VSCP Project
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# VSCP_PATH - set to path to local vscp repository. Default is "../vscp". Set with
# -DVSCP_PATH="path"
#

cmake_minimum_required(VERSION 3.5)
project(vscpl2drv-websrv LANGUAGES CXX C)
set(PACKAGE_AUTHOR "Ake Hedman, the VSCP Project")

# Version settings
if(NOT DEFINED MAJOR_VERSION)
    SET(MAJOR_VERSION "15")
endif()
if(NOT DEFINED MINOR_VERSION)
    SET(MINOR_VERSION "0")
endif()
if(NOT DEFINED PATCH_VERSION)
    SET(PATCH_VERSION "0")
endif()

# Prevent abi warnings in nlohmann
SET(GCC_VSCP_COMPILE_FLAGS "-Wno-psabi")
# Profiling
#SET(GCC_VSCP_LINK_FLAGS    "-lgcov")

SET(CPACK_PACKAGE_DESCRIPTION "VSCP driver for webserver server")
SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "VSCP level II Driver for VSCP that export a server interface for http/https")
SET(CPACK_PACKAGE_VENDOR "the VSCP Project")
SET(CPACK_PACKAGE_CONTACT "akhe@vscp.org")

if(NOT DEFINED APP_LOW_NAME)
  set(APP_LOW_NAME "vscpl2drv-websrv")
endif()

if(NOT DEFINED APP_NAME)
  set(APP_NAME "VSCPL2DEV-websrv")
endif()

if(NOT DEFINED APP_URL)
  set(APP_URL "https://github.com/grodansparadis/vscpl2drv-websrv")
endif()

if(NOT DEFINED APP_VERSION)
  set(APP_VERSION, "${MAJOR_VERSION}.${MINOR_VERSION}.${PATCH_VERSION}")
endif()

# Man build and install
if(NOT DEFINED WIN32)
  add_subdirectory(man)
endif()

option(USE_SSL "Use SSL" TRUE)

## --- C++11 build flags ---
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

# Build locations
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")

option(BUILD_SHARED_LIBS "Build using shared libraries" ON)

# Default location for VSCP level II drivers
set(VSCP_LEVEL2_DRV_DIR /var/lib/vscp/drivers/level2/)



# Generate position-independent code (-fPIC on UNIX)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# --- System Libraries ---
include(GNUInstallDirs)

# --- Path to vscp --- 
if (NOT DEFINED VSCP_PATH)
  set (VSCP_PATH "${PROJECT_SOURCE_DIR}/../vscp/")
endif()

if(WIN32)
	add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-DWIN32_LEAN_AND_MEANS)
    add_definitions(-DOPENSSL_API_1_1)
    add_definitions(-D_POSIX_C_SOURCE)    
    add_definitions(-DVCPKG_TARGET_TRIPLET=x64-windows)
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
    set(LIBS_SYSTEM ws2_32)
elseif(UNIX)
    set(LIBS_SYSTEM c stdc++)
endif()

#   ===========================  cpack  ===========================
IF(EXISTS "${CMAKE_ROOT}/Modules/CPack.cmake")
  INCLUDE(InstallRequiredSystemLibraries)

  IF(WIN32)
    SET(CPACK_SET_DESTDIR OFF)
  ELSE()
    SET(CPACK_SET_DESTDIR ON)
    SET(CPACK_PACKAGING_INSTALL_PREFIX "/var/lib/vscp/drivers")
  ENDIF()

  IF(WIN32)
    SET(CPACK_GENERATOR "NSIS" "ZIP")
  ELSE()
    SET(CPACK_GENERATOR "DEB" "RPM" "TGZ" "ZIP")
  ENDIF()
  
  set(CPACK_PACKAGE_NAME ${APP_LOW_NAME})
  set(CPACK_PACKAGE_INSTALL_REGISTRY_KEY ${APP_NAME})


  SET(CPACK_PACKAGE_VERSION_MAJOR "${MAJOR_VERSION}")
  SET(CPACK_PACKAGE_VERSION_MINOR "${MINOR_VERSION}")
  SET(CPACK_PACKAGE_VERSION_PATCH "${PATCH_VERSION}")
  SET(CPACK_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}_${MAJOR_VERSION}.${MINOR_VERSION}.${CPACK_PACKAGE_VERSION_PATCH}")
  SET(CPACK_SOURCE_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}_${MAJOR_VERSION}.${MINOR_VERSION}.${CPACK_PACKAGE_VERSION_PATCH}")
#  SET(CPACK_IGNORE_FILES "\\.psd$;/CVS/;/\\.svn/;/\\.git/;\\.swp$;/CMakeLists.txt.user;\\.#;/#;\\.tar.gz$;/CMakeFiles/;CMakeCache.txt;\\.qm$;/build/;\\.diff$;.DS_Store'")
#  set(CPACK_SOURCE_IGNORE_FILES ${CPACK_IGNORE_FILES})

  SET(CPACK_NSIS_INSTALLED_ICON_NAME "${APP_LOW_NAME}.ico")
  SET(CPACK_NSIS_HELP_LINK ${APP_URL})
  SET(CPACK_NSIS_URL_INFO_ABOUT ${APP_URL})

  IF(NOT DEFINED WIN32)
    SET(CPACK_DEBIAN_PACKAGE_DEPENDS " libexpat-dev, libssl-dev ")
    SET(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
    SET(CPACK_DEBIAN_PACKAGE_SECTION "network")
    SET(CPACK_DEBIAN_ARCHITECTURE ${CMAKE_SYSTEM_PROCESSOR})
  ENDIF()

  SET(CPACK_COMPONENTS_ALL Libraries ApplicationData)

  # Configure file with custom definitions for NSIS.
  configure_file(
    ${PROJECT_SOURCE_DIR}/resources/nsis/NSIS.definitions.nsh.in
    ${CMAKE_CURRENT_BINARY_DIR}/resources/nsis/NSIS.definitions.nsh
  )

  # Load packaging facilities.
  INCLUDE(CPack)
 
ENDIF(EXISTS "${CMAKE_ROOT}/Modules/CPack.cmake")

set(CMAKE_INCLUDE_CURRENT_DIR ON)

# pthreads
set (THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

#openssl
find_package(OpenSSL REQUIRED)

# Windows Libs
if (WIN32)
    #find_package(pthreads REQUIRED)

    # Expat C library
    find_package(expat CONFIG REQUIRED)
else()

endif()

# Set sockettcp build flags
string(FIND "${OPENSSL_VERSION}" "1.1." SSL_VER_POS)
if(${SSL_VER_POS})
    add_definitions(-DOPENSSL_API_1_0)
else()
    add_definitions(-DOPENSSL_API_1_1)
endif()

# Civetweb defines
#add_definitions(-DDEBUG_TRACE)
add_definitions(-DUSE_IPV6)
add_definitions(-DUSE_WEBSOCKET)
add_definitions(-DLUA_COMPAT_ALL)
add_definitions(-DUSE_LUA)
add_definitions(-DUSE_LUA_SQLITE3)
add_definitions(-DUSE_LUA_FILE_SYSTEM)
add_definitions(-DUSE_DUKTAPE)
add_definitions(-DUSE_SERVER_STATS)
add_definitions(-DUSE_ZLIB)
add_definitions(-DUSE_HTTP2)
add_definitions(-DUSE_4_CGI)
add_definitions(-DUSE_TIMERS)
#add_definitions(-DUSE_X_DOM_SOCKET)

set(RESOURCE_FILES
        README.md
        forms/index.html)

# Add files to library
add_library(vscpl2drv-websrv
    ${CMAKE_CURRENT_SOURCE_DIR}/src/vscpl2drv-websrv.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/webobj.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/webobj.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/websocketsrv.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/websocketsrv.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/web_template.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/web_js.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/web_css.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/websrv.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/websrv.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lua_vscp_func.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lua_vscp_func.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lua_vscp_wrkthread.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lua_vscp_wrkthread.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/restsrv.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/restsrv.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/duktape_vscp_func.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/duktape_vscp_func.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/duktape_vscp_wrkthread.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/duktape_vscp_wrkthread.cpp
    third_party/vscp/src/vscp/common/userlist.h
    third_party/vscp/src/vscp/common/userlist.cpp
    third_party/vscp/src/vscp/common/clientlist.h
    third_party/vscp/src/vscp/common/clientlist.cpp    
    third_party/vscp/src/vscp/common/vscp.h
    third_party/vscp/src/vscp/common/vscpremotetcpif.h
    third_party/vscp/src/vscp/common/vscpremotetcpif.cpp
    third_party/vscp/src/vscp/common/vscpdatetime.h
    third_party/vscp/src/vscp/common/vscpdatetime.cpp
    third_party/vscp/src/vscp/common/guid.h
    third_party/vscp/src/vscp/common/guid.cpp
    third_party/vscp/src/vscp/common/mdf.h
    third_party/vscp/src/vscp/common/mdf.cpp
    third_party/vscp/src/vscp/common/vscphelper.h
    third_party/vscp/src/vscp/common/vscphelper.cpp
    third_party/vscp/src/vscp/common/canal.h
    third_party/vscp/src/common/sockettcp.h
    third_party/vscp/src/common/sockettcp.c
    third_party/vscp/src/common/vscpbase64.h
    third_party/vscp/src/common/vscpbase64.c
    third_party/vscp/src/common/vscp-aes.h
    third_party/vscp/src/common/vscp-aes.c
    third_party/vscp/src/common/crc.h
    third_party/vscp/src/common/crc.c
    third_party/vscp/src/common/crc8.h
    third_party/vscp/src/common/crc8.c
    third_party/vscp/src/common/vscpmd5.h
    third_party/vscp/src/common/vscpmd5.c
    third_party/civetweb/src/civetweb.c
    third_party/civetweb/src/mod_lua.inl
    third_party/Mustache/mustache.hpp
    third_party/spdlog/include
    third_party/duktape-2.7.0/src/duktape.c
    third_party/sqlite3-3.50.4/sqlite3.c
    third_party/lsqlite3.c
    third_party/sqlite3math.c
    third_party/lfs.c
    third_party/LuaXML_lib.c
    third_party/lua_all.c
    

) 

if (WIN32)    
    find_package(pthreads REQUIRED)
    find_path(PTHREAD_INCLUDE_DIR pthread.h)

    include_directories( PUBLIC src/
        third_party/vscp/src/vscp/common/  
        third_party/vscp/src/common
        third_party/Mustache
        third_party/json/include
        third_party/spdlog/include
        third_party/civetweb/src
        third_party/civetweb/include
        third_party/lua
        third_party/duktape
        third_party/sqlite
        ${PThreads4W_INCLUDE_DIR}
        ${CMAKE_BINARY_DIR}
        ${OPENSSL_INCLUDE_DIR}
        ${LOCAL_WIN_INCLUDE}
        ${LOCAL_SYSLOG_INCLUDE} )
else()
    include_directories( PUBLIC src/
        third_party/vscp/src/vscp/common/  
        third_party/vscp/src/common
        third_party/Mustache
        third_party/json/include
        third_party/spdlog/include
        third_party/civetweb/src
        third_party/civetweb/include
        third_party/lua
        third_party/duktape
        third_party/sqlite 
        ${CMAKE_BINARY_DIR}
        ${OPENSSL_INCLUDE_DIR}
        ${LOCAL_SYSLOG_INCLUDE} )
endif()   

if (WIN32)
    target_link_libraries(vscpl2drv-websrv PRIVATE     
        PThreads4W::PThreads4W_CXXEXC
        OpenSSL::SSL 
        OpenSSL::Crypto
        OpenSSL::SSL OpenSSL::Crypto
        expat::expat
    )
        
else()
    target_link_libraries(vscpl2drv-websrv PRIVATE     
        m
        dl
        z
        Threads::Threads
        OpenSSL::SSL 
        OpenSSL::Crypto
        ${EXPAT_LIBRARIES}
    )
endif()

# Install
if(WIN32)
    # Runtime files
    install(TARGETS vscpl2drv-websrv
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
    # Dependencies
    file(GLOB deps_files "${CMAKE_BINARY_DIR}/Release/*.dll")
    install(FILES ${deps_files} DESTINATION ${CMAKE_INSTALL_BINDIR})
    # LICENSE
    install(FILES "${CMAKE_BINARY_DIR}/../LICENSE" DESTINATION "${CMAKE_INSTALL_BINDIR}/..")
    # README
    install(FILES "${CMAKE_BINARY_DIR}/../README.md" DESTINATION "${CMAKE_INSTALL_BINDIR}/..")
else()
    install(TARGETS vscpl2drv-websrv
            LIBRARY DESTINATION ${CMAKE_INSTALL_FULL_}${VSCP_LEVEL2_DRV_DIR}
            RUNTIME DESTINATION ${CMAKE_INSTALL_MANDIR}            
            RESOURCE DESTINATION ${CMAKE_INSTALL_FULL_}/var/lib/vscp/vscpd) 
    install(FILES ${CMAKE_SOURCE_DIR}/resources/linux/websrv.json
            ${CMAKE_SOURCE_DIR}/resources/linux/users.json
            DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/vscpl2drv-websrv/")           
endif()
