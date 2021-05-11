// webobj.cpp: web-interface main class.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version
// 2 of the License, or (at your option) any later version.
//
// This file is part of the VSCP Project (http://www.vscp.org)
//
// Copyright (C) 2000-2021 Ake Hedman,
// the VSCP Project, <akhe@vscp.org>
//
// This file is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this file see the file COPYING.  If not, write to
// the Free Software Foundation, 59 Temple Place - Suite 330,
// Boston, MA 02111-1307, USA.
//

#include <limits.h>
#include <net/if.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <ctype.h>
#include <libgen.h>
#include <net/if.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>

#include <expat.h>

#include <hlo.h>
#include <remotevariablecodes.h>
#include <vscp.h>
#include <vscp_class.h>
#include <vscp_type.h>
#include <vscpdatetime.h>
#include <vscphelper.h>
#include <webdefs.h>
#include <websrv.h>

#include "webobj.h"

#include <json.hpp> // Needs C++11  -std=c++11
#include <mustache.hpp>

#include <spdlog/async.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <fstream>
#include <iostream>
#include <list>
#include <map>
#include <string>

// https://github.com/nlohmann/json
using json = nlohmann::json;
using namespace kainjow::mustache;

// Forward declaration
void*
workerThreadReceive(void* pData);
void*
workerThreadSend(void* pData);

//////////////////////////////////////////////////////////////////////
// CWebObj
//

CWebObj::CWebObj()
{
  m_bDebug       = false;
  m_bWriteEnable = false;
  m_bQuit        = false;

  vscp_clearVSCPFilter(&m_filterIn);  // Accept all events
  vscp_clearVSCPFilter(&m_filterOut); // Send all events
  // m_responseTimeout = TCPIP_DEFAULT_INNER_RESPONSE_TIMEOUT;

  sem_init(&m_semSendQueue, 0, 0);
  sem_init(&m_semReceiveQueue, 0, 0);

  pthread_mutex_init(&m_mutexSendQueue, NULL);
  pthread_mutex_init(&m_mutexReceiveQueue, NULL);

  // Init pool
  spdlog::init_thread_pool(8192, 1);

  // Flush log every five seconds
  spdlog::flush_every(std::chrono::seconds(5));

  auto console = spdlog::stdout_color_mt("console");
  // Start out with level=info. Config may change this
  console->set_level(spdlog::level::debug);
  console->set_pattern("[vscpl2drv-websrv] [%^%l%$] %v");
  spdlog::set_default_logger(console);

  console->debug("Starting the vscpl2drv-websrv...");

  m_bConsoleLogEnable = true;
  m_consoleLogLevel   = spdlog::level::info;
  m_consoleLogPattern = "[vscp] [%^%l%$] %v";

  m_bFileLogEnable   = true;
  m_fileLogLevel     = spdlog::level::info;
  m_fileLogPattern   = "[vscp] [%^%l%$] %v";
  m_path_to_log_file = "/var/log/vscp/vscpl2drv-websrv.log";
  m_max_log_size     = 5242880;
  m_max_log_files    = 7;

  // Set defaults (WEB)
  m_bEnableWebServer    = true;
  m_web_document_root   = "/var/lib/vscp/web/html";
  m_web_listening_ports = "[::]:8888r, [::]:8843s, 8884";
  m_web_index_files     = "index.xhtml, index.html, index.htm ,index.lp, "
                      "index.lsp, index.lua, index.cgi, index.shtml, index.php";
  m_web_authentication_domain = "mydomain.com";
  m_enable_auth_domain_check  = false;

  m_access_log_file = "/var/log/vscp/vscpl2drv-websrv-access.log";
  m_error_log_file  = "/var/log/vscp/vscpl2drv-websrv-error.log";

  m_web_ssl_certificate          = "/srv/vscp/certs/tcpip_server.pem";
  m_web_ssl_certificate_chain    = "";
  m_web_ssl_verify_peer          = false;
  m_web_ssl_ca_path              = "";
  m_web_ssl_ca_file              = "";
  m_web_ssl_verify_depth         = 9;
  m_web_ssl_default_verify_paths = true;
  m_web_ssl_cipher_list          = "DES-CBC3-SHA:AES128-SHA:AES128-GCM-SHA256";
  m_web_ssl_protocol_version     = 3;
  m_web_ssl_short_trust          = false;
  m_web_ssl_cache_timeout        = -1;

  std::string m_web_cgi_interpreter = "";
  std::string m_web_cgi_patterns    = "**.cgi$|**.pl$|**.php|**.py";
  std::string m_web_cgi_environment = "";

  std::string m_web_protect_uri                  = "";
  std::string m_web_throttle                     = "";
  bool m_web_enable_directory_listing            = true;
  bool m_web_enable_keep_alive                   = false;
  long m_web_keep_alive_timeout_ms               = 0;
  std::string m_web_access_control_list          = "";
  std::string m_web_extra_mime_types             = "";
  int m_web_num_threads                          = 50;
  std::string m_web_url_rewrite_patterns         = "";
  std::string m_web_hide_file_patterns           = "";
  long m_web_request_timeout_ms                  = 10000;
  long m_web_linger_timeout_ms                   = 0;
  bool m_web_decode_url                          = true;
  std::string m_web_global_auth_file             = "";
  std::string m_web_per_directory_auth_file      = "";
  std::string m_web_ssi_patterns                 = "";
  std::string m_web_access_control_allow_origin  = "*";
  std::string m_web_access_control_allow_methods = "*";
  std::string m_web_access_control_allow_headers = "*";
  std::string m_web_error_pages                  = "";
  long m_web_tcp_nodelay                         = 0;
  std::string m_web_static_file_cache_control    = "";
  long m_web_static_file_max_age                 = 3600;
  long m_web_strict_transport_security_max_age   = 0;
  bool m_web_allow_sendfile_call                 = true;
  std::string m_web_additional_header            = "";
  long m_web_max_request_size                    = 16384;
  bool m_web_allow_index_script_resource         = false;

  std::string m_web_duktape_script_patterns = "**.ssjs$";

  std::string m_web_lua_preload_file         = "";
  std::string m_web_lua_script_patterns      = "**.lua$";
  std::string m_web_lua_server_page_patterns = "**.lp$|**.lsp$";
  std::string m_web_lua_websocket_patterns =
    VSCPDB_CONFIG_DEFAULT_WEB_LUA_WEBSOCKET_PATTERN;
  std::string m_web_lua_background_script        = "";
  std::string m_web_lua_background_script_params = "";

  m_web_run_as_user    = "";
  m_web_case_sensitive = false;

  m_bEnableWebsockets       = true;
  m_websocket_document_root = VSCPDB_CONFIG_DEFAULT_WEBSOCKET_DOCUMENT_ROOT;
  m_websocket_timeout_ms    = 10000;
  bool bEnable_websocket_ping_pong = true;

  m_bEnableRestApi = true;
}

//////////////////////////////////////////////////////////////////////
// ~CWebObj
//

CWebObj::~CWebObj()
{
  close();

  sem_destroy(&m_semSendQueue);
  sem_destroy(&m_semReceiveQueue);

  pthread_mutex_destroy(&m_mutexSendQueue);
  pthread_mutex_destroy(&m_mutexReceiveQueue);

  // Shutdown logger in a nice way
  spdlog::drop_all();
  spdlog::shutdown();
}

//////////////////////////////////////////////////////////////////////
// sendEvent
//

bool
CWebObj::sendEvent(vscpEventEx* pex)
{
  return true;
}

//////////////////////////////////////////////////////////////////////
// sendEvent
//

bool
CWebObj::sendEvent(vscpEvent* pev)
{
  return true;
}

// ----------------------------------------------------------------------------

//////////////////////////////////////////////////////////////////////
// open
//
//

bool
CWebObj::open(std::string& path, const cguid& guid)
{
  // Set GUID
  m_guid = guid;

  // Save path to config file
  m_path = path;

  // Read configuration file
  if (!doLoadConfig()) {
    spdlog::get("logger")->critical("Failed to load configuration file [{}]",
                                    path);
    return false;
  }

  // Start the web server
  try {
    start_webserver(this);
  }
  catch (...) {
    spdlog::get("logger")->error("Exception when starting web server");
    return false;
  }

  // start the workerthread
  if (pthread_create(&m_pthreadSend, NULL, workerThreadSend, this)) {
    spdlog::get("logger")->error("Unable to start send worker thread.");
    return false;
  }

  if (pthread_create(&m_pthreadReceive, NULL, workerThreadReceive, this)) {
    spdlog::get("logger")->error("Unable to start receive worker thread.");
    return false;
  }

  return true;
}

//////////////////////////////////////////////////////////////////////
// close
//

void
CWebObj::close(void)
{
  // Do nothing if already terminated
  if (m_bQuit)
    return;

  m_bQuit = true; // terminate the thread
  sleep(1);       // Give the thread some time to terminate
}

// ----------------------------------------------------------------------------

/////////////////////////////////////////////////////////////////////////////
// readEncryptionKey
//

bool
CWebObj::readEncryptionKey(const std::string& path)
{
  bool rv = false; // Be negative today

  try {
    std::string vscpkey;
    std::ifstream in(path, std::ifstream::in);
    std::stringstream strStream;
    strStream << in.rdbuf();
    vscpkey = strStream.str();
    vscp_trim(vscpkey);
    spdlog::get("logger")->debug("vscp.key [{}]", vscpkey.c_str());
    rv = vscp_hexStr2ByteArray(m_vscp_key, 32, vscpkey.c_str());
  }
  catch (...) {
    spdlog::get("logger")->error("Failed to read encryption key file [{}]",
                                 m_path.c_str());
  }

  return rv;
}

//////////////////////////////////////////////////////////////////////
// doLoadConfig
//

bool
CWebObj::doLoadConfig(void)
{
  try {
    std::ifstream in(m_path, std::ifstream::in);
    in >> m_j_config;
  }
  catch (json::parse_error& e) {
    spdlog::critical(
      "Failed to load/parse JSON configuration. message: {}, id: {}, pos: {} ",
      e.what(),
      e.id,
      e.byte);
    return false;
  }
  catch (...) {
    spdlog::critical("Unknown exception when loading JSON configuration.");
    return false;
  }

  spdlog::debug("Reading configuration from [{}]", m_path);

  // Logging
  if (m_j_config.contains("logging") && m_j_config["logging"].is_object()) {

    json j = m_j_config["logging"];

    // * * *  CONSOLE  * * *

    // Logging: console-log-enable
    if (j.contains("console-enable")) {
      try {
        m_bConsoleLogEnable = j["console-enable"].get<bool>();
      }
      catch (const std::exception& ex) {
        spdlog::error("Failed to read 'console-enable' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("Failed to read 'console-enable' due to unknown error.");
      }
    }
    else {
      spdlog::debug(
        "Failed to read LOGGING 'console-enable' Defaults will be used.");
    }

    // Logging: console-log-level
    if (j.contains("console-level")) {
      std::string str;
      try {
        str = j["console-level"].get<std::string>();
      }
      catch (const std::exception& ex) {
        spdlog::error("Failed to read 'console-level' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("Failed to read 'console-level' due to unknown error.");
      }
      vscp_makeLower(str);
      if (std::string::npos != str.find("off")) {
        m_consoleLogLevel = spdlog::level::off;
      }
      else if (std::string::npos != str.find("critical")) {
        m_consoleLogLevel = spdlog::level::critical;
      }
      else if (std::string::npos != str.find("err")) {
        m_consoleLogLevel = spdlog::level::err;
      }
      else if (std::string::npos != str.find("warn")) {
        m_consoleLogLevel = spdlog::level::warn;
      }
      else if (std::string::npos != str.find("info")) {
        m_consoleLogLevel = spdlog::level::info;
      }
      else if (std::string::npos != str.find("debug")) {
        m_consoleLogLevel = spdlog::level::debug;
      }
      else if (std::string::npos != str.find("trace")) {
        m_consoleLogLevel = spdlog::level::trace;
      }
      else {
        spdlog::error("Failed to read LOGGING 'console-level' has invalid "
                      "value [{}]. Default value used.",
                      str);
      }
    }
    else {
      spdlog::error(
        "Failed to read LOGGING 'console-level' Defaults will be used.");
    }

    // Logging: console-log-pattern
    if (j.contains("console-pattern")) {
      try {
        m_consoleLogPattern = j["console-pattern"].get<std::string>();
      }
      catch (const std::exception& ex) {
        spdlog::error("Failed to read 'console-pattern' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("Failed to read 'console-pattern' due to unknown error.");
      }
    }
    else {
      spdlog::debug(
        "Failed to read LOGGING 'console-pattern' Defaults will be used.");
    }

    // * * *  FILE  * * *

    // Logging: file-log-enable
    if (j.contains("file-enable")) {
      try {
        m_bFileLogEnable = j["file-enable"].get<bool>();
      }
      catch (const std::exception& ex) {
        spdlog::error("Failed to read 'file-enable' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("Failed to read 'file-enable' due to unknown error.");
      }
    }
    else {
      spdlog::debug(
        "Failed to read LOGGING 'file-enable' Defaults will be used.");
    }

    // Logging: file-log-level
    if (j.contains("file-level")) {
      std::string str;
      try {
        str = j["file-level"].get<std::string>();
      }
      catch (const std::exception& ex) {
        spdlog::error("Failed to read 'file-level' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("Failed to read 'file-level' due to unknown error.");
      }
      vscp_makeLower(str);
      if (std::string::npos != str.find("off")) {
        m_fileLogLevel = spdlog::level::off;
      }
      else if (std::string::npos != str.find("critical")) {
        m_fileLogLevel = spdlog::level::critical;
      }
      else if (std::string::npos != str.find("err")) {
        m_fileLogLevel = spdlog::level::err;
      }
      else if (std::string::npos != str.find("warn")) {
        m_fileLogLevel = spdlog::level::warn;
      }
      else if (std::string::npos != str.find("info")) {
        m_fileLogLevel = spdlog::level::info;
      }
      else if (std::string::npos != str.find("debug")) {
        m_fileLogLevel = spdlog::level::debug;
      }
      else if (std::string::npos != str.find("trace")) {
        m_fileLogLevel = spdlog::level::trace;
      }
      else {
        spdlog::error("Failed to read LOGGING 'file-level' has invalid value "
                      "[{}]. Default value used.",
                      str);
      }
    }
    else {
      spdlog::error(
        "Failed to read LOGGING 'file-level' Defaults will be used.");
    }

    // Logging: file-log-pattern
    if (j.contains("file-pattern")) {
      try {
        m_fileLogPattern = j["file-pattern"].get<std::string>();
      }
      catch (const std::exception& ex) {
        spdlog::error("Failed to read 'file-pattern' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("Failed to read 'file-pattern' due to unknown error.");
      }
    }
    else {
      spdlog::debug(
        "Failed to read LOGGING 'file-pattern' Defaults will be used.");
    }

    // Logging: file-path
    if (j.contains("file-path")) {
      try {
        m_path_to_log_file = j["file-path"].get<std::string>();
      }
      catch (const std::exception& ex) {
        spdlog::error("Failed to read 'file-path' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("Failed to read 'file-path' due to unknown error.");
      }
    }
    else {
      spdlog::error(
        " Failed to read LOGGING 'file-path' Defaults will be used.");
    }

    // Logging: file-max-size
    if (j.contains("file-max-size")) {
      try {
        m_max_log_size = j["file-max-size"].get<uint32_t>();
      }
      catch (const std::exception& ex) {
        spdlog::error("Failed to read 'file-max-size' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("Failed to read 'file-max-size' due to unknown error.");
      }
    }
    else {
      spdlog::error(
        "Failed to read LOGGING 'file-max-size' Defaults will be used.");
    }

    // Logging: file-max-files
    if (j.contains("file-max-files")) {
      try {
        m_max_log_files = j["file-max-files"].get<uint16_t>();
      }
      catch (const std::exception& ex) {
        spdlog::error("Failed to read 'file-max-files' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("Failed to read 'file-max-files' due to unknown error.");
      }
    }
    else {
      spdlog::error(
        "Failed to read LOGGING 'file-max-files' Defaults will be used.");
    }

  } // Logging
  else {
    spdlog::error("No logging has been setup.");
  }

  ///////////////////////////////////////////////////////////////////////////
  //                          Setup logger
  ///////////////////////////////////////////////////////////////////////////

  // Console log
  auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
  if (m_bConsoleLogEnable) {
    console_sink->set_level(m_consoleLogLevel);
    console_sink->set_pattern(m_consoleLogPattern);
  }
  else {
    // If disabled set to off
    console_sink->set_level(spdlog::level::off);
  }

  // auto rotating =
  // std::make_shared<spdlog::sinks::rotating_file_sink_mt>("log_filename",
  // 1024*1024, 5, false);
  auto rotating_file_sink =
    std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
      m_path_to_log_file.c_str(),
      m_max_log_size,
      m_max_log_files);

  if (m_bFileLogEnable) {
    rotating_file_sink->set_level(m_fileLogLevel);
    rotating_file_sink->set_pattern(m_fileLogPattern);
  }
  else {
    // If disabled set to off
    rotating_file_sink->set_level(spdlog::level::off);
  }

  std::vector<spdlog::sink_ptr> sinks{ console_sink, rotating_file_sink };
  auto logger = std::make_shared<spdlog::async_logger>(
    "logger",
    sinks.begin(),
    sinks.end(),
    spdlog::thread_pool(),
    spdlog::async_overflow_policy::block);
  // The separate sub loggers will handle trace levels
  logger->set_level(spdlog::level::trace);
  spdlog::register_logger(logger);

  // ------------------------------------------------------------------------

  // write
  if (m_j_config.contains("write")) {
    try {
      m_bWriteEnable = m_j_config["write"].get<bool>();
      spdlog::debug("bWriteEnable set to {}", m_bWriteEnable);
    }
    catch (const std::exception& ex) {
      spdlog::error("Failed to read 'write' Error='{}'", ex.what());
    }
    catch (...) {
      spdlog::error("Failed to read 'write' due to unknown error.");
    }
  }
  else {
    spdlog::error("Failed to read 'write' item from configuration file. "
                  "Defaults will be used.");
  }

  // VSCP key file
  if (m_j_config.contains("key-file") && m_j_config["key-file"].is_string()) {
    if (!readEncryptionKey(m_j_config["key-file"].get<std::string>())) {
      spdlog::warn("Failed to read VSCP key from file [{}]. Default key will "
                   "be used. Dangerous!",
                   m_j_config["key-file"].get<std::string>());
    }
    else {
      spdlog::debug("key-file {} read successfully",
                    m_j_config["key-file"].get<std::string>());
    }
  }
  else {
    spdlog::warn(
      "VSCP key file is not defined. Default key will be used. Dangerous!");
  }

  // Path to user database
  if (m_j_config.contains("path-users")) {
    try {
      m_pathUsers = m_j_config["path-users"].get<std::string>();
      if (!m_userList.loadUsersFromFile(m_pathUsers)) {
        spdlog::critical(
          "Failed to load users from file 'user-path'='{}'. Terminating!",
          m_pathUsers);
        return false;
      }
    }
    catch (const std::exception& ex) {
      spdlog::error("Failed to read 'path-users' Error='{}'", ex.what());
    }
    catch (...) {
      spdlog::error("Failed to read 'path-users' due to unknown error.");
    }
  }
  else {
    spdlog::warn("Failed to read 'path-users' Defaults will be used.");
  }

  // Filter
  if (m_j_config.contains("filter") && m_j_config["filter"].is_object()) {

    json j = m_j_config["filter"];

    // IN filter
    if (j.contains("in-filter")) {
      try {
        std::string str = j["in-filter"].get<std::string>();
        vscp_readFilterFromString(&m_filterIn, str.c_str());
      }
      catch (const std::exception& ex) {
        spdlog::error(" Failed to read 'in-filter' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error(" Failed to read 'in-filter' due to unknown error.");
      }
    }
    else {
      spdlog::debug(
        " Failed to read LOGGING 'in-filter' Defaults will be used.");
    }

    // IN mask
    if (j.contains("in-mask")) {
      try {
        std::string str = j["in-mask"].get<std::string>();
        vscp_readMaskFromString(&m_filterIn, str.c_str());
      }
      catch (const std::exception& ex) {
        spdlog::error(" Failed to read 'in-mask' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error(" Failed to read 'in-mask' due to unknown error.");
      }
    }
    else {
      spdlog::debug(" Failed to read 'in-mask' Defaults will be used.");
    }

    // OUT filter
    if (j.contains("out-filter")) {
      try {
        std::string str = j["in-filter"].get<std::string>();
        vscp_readFilterFromString(&m_filterOut, str.c_str());
      }
      catch (const std::exception& ex) {
        spdlog::error(" Failed to read 'out-filter' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error(" Failed to read 'out-filter' due to unknown error.");
      }
    }
    else {
      spdlog::debug(" Failed to read 'out-filter' Defaults will be used.");
    }

    // OUT mask
    if (j.contains("out-mask")) {
      try {
        std::string str = j["out-mask"].get<std::string>();
        vscp_readMaskFromString(&m_filterOut, str.c_str());
      }
      catch (const std::exception& ex) {
        spdlog::error(" Failed to read 'out-mask' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error(" Failed to read 'out-mask' due to unknown error.");
      }
    }
    else {
      spdlog::debug(" Failed to read 'out-mask' Defaults will be used.");
    }
  }

  //*************************************************************************
  //                             WEB-Server
  //*************************************************************************

  // https://github.com/civetweb/civetweb/blob/master/docs/UserManual.md

  if (m_j_config.contains("web") && m_j_config["web"].is_object()) {

    json j = m_j_config["web"];

    // Enable web server
    if (j.contains("enable") && j["enable"].is_boolean()) {
      m_bEnableWebServer = j["enable"].get<bool>();
    }

    // document-root: .
    // A directory to serve. By default, the current working directory is
    // served. The current directory is commonly referenced as dot (.). It is
    // recommended to use an absolute path for document_root, in order to avoid
    // accidentally serving the wrong directory.

    if (j.contains("document-root") && j["document-root"].is_string()) {
      m_web_document_root = j["document-root"].get<std::string>();
    }

    // listening_ports: 8080
    // Comma-separated list of ports to listen on. If the port is SSL, a letter
    // s must be appended, for example, 80,443s will open port 80 and port 443,
    // and connections on port 443 will be SSL-ed. For non-SSL ports, it is
    // allowed to append letter r, meaning 'redirect'. Redirect ports will
    // redirect all their traffic to the first configured SSL port. For example,
    // if listening_ports is 80r,443s, then all HTTP traffic coming at port 80
    // will be redirected to HTTPS port 443.
    //
    // It is possible to specify an IP address to bind to. In this case, an IP
    // address and a colon must be pre-pended to the port number. For example,
    // to bind to a loopback interface on port 80 and to all interfaces on HTTPS
    // port 443, use 127.0.0.1:80,443s.
    //
    // If the server is built with IPv6 support, [::]:8080 can be used to listen
    // to IPv6 connections to port 8080. IPv6 addresses of network interfaces
    // can be specified as well, e.g. [::1]:8080 for the IPv6 loopback
    // interface.
    //
    // [::]:80 will bind to port 80 IPv6 only. In order to use port 80 for all
    // interfaces, both IPv4 and IPv6, use either the configuration 80,[::]:80
    // (create one socket for IPv4 and one for IPv6 only), or +80 (create one
    // socket for both, IPv4 and IPv6). The + notation to use IPv4 and IPv6 will
    // only work if no network interface is specified. Depending on your
    // operating system version and IPv6 network environment, some
    // configurations might not work as expected, so you have to test to find
    // the configuration most suitable for your needs. In case +80 does not work
    // for your environment, you need to use 80,[::]:80.
    //
    // It is possible to use network interface addresses (e.g., 192.0.2.3:80,
    // [2001:0db8::1234]:80). To get a list of available network interface
    // addresses, use ipconfig (in a cmd window in Windows) or ifconfig (in a
    // Linux shell). Alternatively, you could use the hostname for an interface.
    // Check the hosts file of your operating system for a proper hostname (for
    // Windows, usually found in C:\Windows\System32\drivers\etc, for most Linux
    // distributions: /etc/hosts). E.g., to bind the IPv6 local host, you could
    // use ip6-localhost:80. This translates to [::1]:80. Beside the hosts file,
    // there are several other name resolution services. Using your hostname
    // might bind you to the localhost or an external interface. You could also
    // try hostname.local, if the proper network services are installed
    // (Zeroconf, mDNS, Bonjour, Avahi). When using a hostname, you need to test
    // in your particular network environment - in some cases, you might need to
    // resort to a fixed IP address.
    //
    // If you want to use an ephemeral port (i.e. let the operating system
    // choose a port number), use 0 for the port number. This will make it
    // necessary to communicate the port number to clients via other means, for
    // example mDNS (Zeroconf, Bonjour, Avahi).
    //
    // In case the server has been built with the USE_X_DOM_SOCKET option set,
    // it can listen to unix domain sockets as well. They are specified by a
    // lower case x followed by the domain socket path, e.g. x/tmp/sockname.
    // Domain sockets do not require a port number, always use HTTP (not HTTPS)
    // and never redirect. Thus : is not allowed, while r or s at the end of the
    // configuration is interpreted as part of the domain socket path. The
    // domain socket path must be a valid path to a non-existing file on a
    // Unix/Linux system. The CivetWeb process needs write/create access rights
    // to create the domain socket in the Unix/Linux file system. Use only
    // alphanumerical characters, underscore and / in a domain socket path (in
    // particular, ,;: must be avoided).
    //
    // All socket/protocol types may be combined, separated by ,. E.g.:
    // 127.0.0.1:80,[::1]:80,x/tmp/sockname will listen to localhost http
    // connections using IPv4, IPv6 and the domain socket /tmp/sockname.

    if (j.contains("listening-ports") && j["listening-ports"].is_array()) {
      std::string str;
      for (json::iterator it = j["listening-ports"].begin();
           it != j["listening-ports"].end();
           ++it) {
        if (str.length())
          str += ",";
        str += *it;
      }
      m_web_listening_ports = str;
    }
    else if (j.contains("listening-ports") &&
             j["listening-ports"].is_string()) {
      m_web_listening_ports = j["listening-ports"].get<std::string>();
    }

    // authentication-domain
    // Authorization realm used for HTTP digest authentication. This domain is
    // used in the encoding of the .htpasswd authorization files as well.
    // Changing the domain retroactively will render the existing passwords
    // useless.

    if (j.contains("authentication-domain") &&
        j["authentication-domain"].is_string()) {
      m_web_authentication_domain =
        j["authentication-domain"].get<std::string>();
    }

    // index-files:
    // index.xhtml,index.html,index.htm,index.cgi,index.shtml,index.php
    // Comma-separated list of files to be treated as directory index files. If
    // more than one matching file is present in a directory, the one listed to
    // the left is used as a directory index.
    //
    // In case built-in Lua support has been enabled,
    // index.lp,index.lsp,index.lua are additional default index files, ordered
    // before index.cgi.

    if (j.contains("index-files") && j["index-files"].is_array()) {
      std::string str;
      for (json::iterator it = j["index-files"].begin();
           it != j["index-files"].end();
           ++it) {
        if (str.length())
          str += ",";
        str += *it;
      }
      m_web_index_files = str;
    }
    else if (j.contains("index-files") && j["index-files"].is_string()) {
      m_web_index_files = j["index-files"].get<std::string>();
    }

    // enable-auth-domain-check: yes
    // When using absolute URLs, verify the host is identical to the
    // authentication_domain. If enabled, requests to absolute URLs will only be
    // processed if they are directed to the domain. If disabled, absolute URLs
    // to any host will be accepted.

    if (j.contains("enable-auth-domain-check") &&
        j["enable-auth-domain-check"].is_boolean()) {
      m_enable_auth_domain_check = j["enable-auth-domain-check"].get<bool>();
    }

    // access-log-file : ""
    // Path to a file for access logs. Either full path, or relative to the
    // current working directory. If absent (default), then accesses are not
    // logged.

    if (j.contains("access-log-file") && j["access-log-file"].is_string()) {
      m_access_log_file = j["access-log-file"].get<std::string>();
    }

    // error-log-file: ""
    // Path to a file for error logs. Either full path, or relative to the
    // current working directory. If absent (default), then errors are not
    // logged.

    if (j.contains("error-log-file") && j["error-log-file"].is_string()) {
      m_error_log_file = j["error-log-file"].get<std::string>();
    }

    // protect-uri : Comma separated list of URI=PATH pairs, specifying that
    // given URIs must be protected with password files specified by PATH.
    // All Paths must be full file paths.
    if (j.contains("protect-uri") && j["protect-uri"].is_array()) {
      std::string str;
      for (json::iterator it = j["protect-uri"].begin();
           it != j["protect-uri"].end();
           ++it) {
        if (str.length())
          str += ",";
        str += *it;
      }
      m_web_protect_uri = str;
    }
    else if (j.contains("protect-uri") && j["protect-uri"].is_string()) {
      m_web_protect_uri = j["protect-uri"].get<std::string>();
    }

    // throttle : Limit download speed for clients. throttle is a
    // comma-separated list of key=value pairs, where key could be:
    //
    //  *                   limit speed for all connections
    // x.x.x.x/mask        limit speed for specified subnet
    // [IPv6-addr]/mask    limit speed for specified IPv6 subnet (needs square
    // brackets) uri_prefix_pattern  limit speed for given URIs The value is a
    // floating-point number of bytes per second, optionally followed by a k or
    // m character, meaning kilobytes and megabytes respectively. A limit of 0
    // means unlimited rate. The last matching rule wins. Examples:
    //
    // *=1k,10.0.0.0/8=0   limit all accesses to 1 kilobyte per second,
    //                     but give connections the from 10.0.0.0/8 subnet
    //                     unlimited speed
    //
    // /downloads/=5k      limit accesses to all URIs in `/downloads/` to
    //                     5 kilobytes per second. All other accesses are
    //                     unlimited

    if (j.contains("throttle") && j["throttle"].is_array()) {
      std::string str;
      for (json::iterator it = j["throttle"].begin(); it != j["throttle"].end();
           ++it) {
        if (str.length())
          str += ",";
        str += *it;
      }
      m_web_throttle = str;
    }
    else if (j.contains("throttle") && j["throttle"].is_string()) {
      m_web_throttle = j["throttle"].get<std::string>();
    }

    // enable-directory-listing : true,
    // Enable directory listing, either yes or no.

    if (j.contains("enable-directory-listing") &&
        j["enable-directory-listing"].is_boolean()) {
      m_web_enable_directory_listing =
        j["enable-directory-listing"].get<bool>();
    }

    // enable-keep-alive : "false",
    // Enable connection keep alive, either yes or no.
    // Allows clients to reuse TCP connection for subsequent HTTP requests,
    // which improves performance. For this to work when using request handlers
    // it is important to add the correct Content-Length HTTP header for each
    // request. If this is forgotten the client will time out.
    //
    // Note: If you set keep_alive to yes, you should set keep_alive_timeout_ms
    // to some value > 0 (e.g. 500). If you set keep_alive to no, you should set
    // keep_alive_timeout_ms to 0. Currently, this is done as a default value,
    // but this configuration is redundant. In a future version, the keep_alive
    // configuration option might be removed and automatically set to yes if a
    // timeout > 0 is set.

    if (j.contains("enable-keep-alive") &&
        j["enable-keep-alive"].is_boolean()) {
      m_web_enable_keep_alive = j["enable-keep-alive"].get<bool>();
    }

    // keep-alive-timeout_ms : 0/500,
    // Idle timeout between two requests in one keep-alive connection. If keep
    // alive is enabled, multiple requests using the same connection are
    // possible. This reduces the overhead for opening and closing connections
    // when loading several resources from one server, but it also blocks one
    // port and one thread at the server during the lifetime of this connection.
    // Unfortunately, browsers do not close the keep-alive connection after
    // loading all resources required to show a website. The server closes a
    // keep-alive connection, if there is no additional request from the client
    // during this timeout.
    //
    // Note: if enable_keep_alive is set to no the value of
    // keep_alive_timeout_ms should be set to 0, if enable_keep_alive is set to
    // yes, the value of keep_alive_timeout_ms must be >0. Currently
    // keep_alive_timeout_ms is ignored if enable_keep_alive is no, but future
    // versions may drop the enable_keep_alive configuration value and
    // automatically use keep-alive if keep_alive_timeout_ms is not 0.

    if (j.contains("keep-alive-timeout-ms") &&
        j["keep-alive-timeout-ms"].is_number()) {
      m_web_keep_alive_timeout_ms = j["keep-alive-timeout-ms"].get<long>();
    }

    // access-control-list : "",
    // An Access Control List (ACL) allows restrictions to be put on the list of
    // IP addresses which have access to the web server. In the case of the
    // CivetWeb web server, the ACL is a comma separated list of IP subnets,
    // where each subnet is pre-pended by either a - or a + sign. A plus sign
    // means allow, where a minus sign means deny. If a subnet mask is omitted,
    // such as -1.2.3.4, this means to deny only that single IP address.
    //
    // If this value is not set, all accesses are allowed. Otherwise, the
    // default setting is to deny all accesses. On each request the full list is
    // traversed, and the last match wins. Examples:
    //
    // +192.168.0.0/16,+fe80::/64 deny all accesses, allow 192.168.0.0/16 and
    // fe80::/64 subnet
    //                            (The second one is valid only if IPv6 support
    //                            is enabled)
    // To learn more about subnet masks, see the Wikipedia page on Subnetwork.

    if (j.contains("access-control-list") &&
        j["access-control-list"].is_string()) {
      m_web_access_control_list = j["access-control-list"].get<std::string>();
    }

    // extra-mime-types : "",
    // Extra mime types, in the form extension1=type1,exten-sion2=type2,....
    // See the Wikipedia page on Internet media types. Extension must include a
    // leading dot. Example: .cpp=plain/text,.java=plain/text

    if (j.contains("extra-mime-types") && j["extra-mime-types"].is_array()) {
      std::string str;
      for (json::iterator it = j["extra-mime-types"].begin();
           it != j["extra-mime-types"].end();
           ++it) {
        if (str.length())
          str += ",";
        str += *it;
      }
      m_web_extra_mime_types = str;
    }
    else if (j.contains("extra-mime-types") &&
             j["extra-mime-types"].is_string()) {
      m_web_extra_mime_types = j["extra-mime-types"].get<std::string>();
    }

    // num-threads : 50,
    // Number of worker threads. CivetWeb handles each incoming connection in a
    // separate thread. Therefore, the value of this option is effectively the
    // number of concurrent HTTP connections CivetWeb can handle.
    //
    // If there are more simultaneous requests (connection attempts), they are
    // queued. Every connection attempt first needs to be accepted (up to a
    // limit of listen_backlog waiting connections). Then it is accepted and
    // queued for the next available worker thread (up to a limit of
    // connection_queue). Finally a worker thread handles all requests received
    // in a connection (up to num_threads).
    //
    // In case the clients are web browsers, it is recommended to use
    // num_threads of at least 5, since browsers often establish multiple
    // connections to load a single web page, including all linked documents
    // (CSS, JavaScript, images, ...).

    if (j.contains("num-threads") && j["num-threads"].is_number()) {
      m_web_num_threads = j["num-threads"].get<int>();
    }

    // url-rewrite-patterns : "",
    // Comma-separated list of URL rewrites in the form of
    // uri_pattern=file_or_directory_path. When CivetWeb receives any request,
    // it constructs the file name to show by combining document_root and the
    // URI. However, if the rewrite option is used and uri_pattern matches the
    // requested URI, then document_root is ignored. Instead,
    // file_or_directory_path is used, which should be a full path name or a
    // path relative to the web server's current working directory. Note that
    // uri_pattern, as all CivetWeb patterns, is a prefix pattern.
    //
    // This makes it possible to serve many directories outside from
    // document_root, redirect all requests to scripts, and do other tricky
    // things. For example, to redirect all accesses to .doc files to a special
    // script, do:
    //
    // CivetWeb -url_rewrite_patterns **.doc$=/path/to/cgi-bin/handle_doc.cgi
    // Or, to imitate support for user home directories, do:
    //
    // CivetWeb -url_rewrite_patterns /~joe/=/home/joe/,/~bill=/home/bill/

    if (j.contains("url-rewrite-patterns") &&
        j["url-rewrite-patterns"].is_string()) {
      m_web_url_rewrite_patterns = j["url-rewrite-patterns"].get<std::string>();
    }

    // hide-file-patterns : "",
    // A pattern for the files to hide. Files that match the pattern will not
    // show up in directory listing and return 404 Not Found if requested.
    // Pattern must be for a file name only, not including directory names.
    // Example:
    //
    // CivetWeb -hide_files_patterns secret.txt|**.hide
    // Note: hide_file_patterns uses the pattern described above. If you want to
    // hide all files with a certain extension, make sure to use **.extension
    // (not just *.extension).

    if (j.contains("hide-file-patterns") &&
        j["hide-file-patterns"].is_string()) {
      m_web_hide_file_patterns = j["hide-file-patterns"].get<std::string>();
    }

    // request-timeout-ms : 30000
    // Timeout for network read and network write operations, in milliseconds.
    // If a client intends to keep long-running connection, either increase this
    // value or (better) use keep-alive messages.

    if (j.contains("request-timeout-ms") &&
        j["request-timeout-ms"].is_number()) {
      m_web_request_timeout_ms = j["request-timeout-ms"].get<long>();
    }

    // linger-timeout-ms : "",
    if (j.contains("linger-timeout-ms") && j["linger-timeout-ms"].is_number()) {
      m_web_linger_timeout_ms = j["linger-timeout-ms"].get<long>();
    }

    // decode-url : true
    // URL encoded request strings are decoded in the server, unless it is
    // disabled by setting this option to no.

    if (j.contains("decode-url") && j["decode-url"].is_boolean()) {
      m_web_decode_url = j["decode-url"].get<bool>();
    }

    // global-auth-file : "",
    if (j.contains("global-auth-file") && j["global-auth-file"].is_string()) {
      m_web_global_auth_file = j["global-auth-file"].get<std::string>();
    }

    // per-directory-auth-file : "",
    // Path to a global passwords file, either full path or relative to the
    // current working directory. If set, per-directory .htpasswd files are
    // ignored, and all requests are authorized against that file.
    //
    // The file has to include the realm set through authentication_domain and
    // the password in digest format:
    //
    // user:realm:digest
    // test:test.com:ce0220efc2dd2fad6185e1f1af5a4327
    // Password files may be generated using CivetWeb -A as explained above, or
    // online tools e.g. this generator
    // http://www.askapache.com/online-tools/htpasswd-generator

    if (j.contains("per-directory-auth-file") &&
        j["per-directory-auth-file"].is_string()) {
      m_web_per_directory_auth_file =
        j["per-directory-auth-file"].get<std::string>();
    }

    // ssi-patterns : "**.shtml$|**.shtm$"
    // All files that match ssi_pattern are treated as Server Side Includes
    // (SSI).
    //
    // SSI is a simple interpreted server-side scripting language which is most
    // commonly used to include the contents of another file in a web page. It
    // can be useful when it is desirable to include a common piece of code
    // throughout a website, for example, headers and footers.
    //
    // In order for a webpage to recognize an SSI-enabled HTML file, the
    // filename should end with a special extension, by default the extension
    // should be either .shtml or .shtm. These extensions may be changed using
    // the ssi_pattern option.
    //
    // Unknown SSI directives are silently ignored by CivetWeb. Currently, two
    // SSI directives are supported,
    // <!--#include ...> and <!--#exec "command">. Note that the <!--#include
    // ...> directive supports three path specifications:
    //
    // <!--#include virtual="path">  Path is relative to web server root
    // <!--#include abspath="path">  Path is absolute or relative to
    //                               web server working dir
    // <!--#include file="path">,    Path is relative to current document
    // <!--#include "path">
    // The include directive may be used to include the contents of a file or
    // the result of running a CGI script. The exec directive is used to execute
    // a command on a server, and show the output that would have been printed
    // to stdout (the terminal window) otherwise. Example:
    //
    // <!--#exec "ls -l" -->
    // For more information on Server Side Includes, take a look at the
    // Wikipedia: Server Side Includes
    // http://en.wikipedia.org/wiki/Server_Side_Includes

    if (j.contains("ssi-patterns") && j["ssi-patterns"].is_string()) {
      m_web_ssi_patterns = j["ssi-patterns"].get<std::string>();
    }

    // access-control-allow-origin : "*"
    // Access-Control-Allow-Origin header field, used for cross-origin resource
    // sharing (CORS). See the Wikipedia page on CORS.
    // http://en.wikipedia.org/wiki/Cross-origin_resource_sharing

    if (j.contains("access-control-allow-origin") &&
        j["access-control-allow-origin"].is_string()) {
      m_web_access_control_allow_origin =
        j["access-control-allow-origin"].get<std::string>();
    }

    // access-control-allow-methods : "*"
    // Access-Control-Allow-Methods header field, used for cross-origin resource
    // sharing (CORS) pre-flight requests. See the Wikipedia page on CORS.
    //
    // If set to an empty string, pre-flights will not be supported directly by
    // the server, but scripts may still support pre-flights by handling the
    // OPTIONS method properly. If set to "*", the pre-flight will allow
    // whatever method has been requested. If set to a comma separated list of
    // valid HTTP methods, the pre-flight will return exactly this list as
    // allowed method. If set in any other way, the result is unspecified.

    if (j.contains("access-control-allow-methods") &&
        j["access-control-allow-methods"].is_string()) {
      m_web_access_control_allow_methods =
        j["access-control-allow-methods"].get<std::string>();
    }

    // access-control-allow-headers : "*"
    // Access-Control-Allow-Headers header field, used for cross-origin resource
    // sharing (CORS) pre-flight requests. See the Wikipedia page on CORS.
    //
    // If set to an empty string, pre-flights will not allow additional headers.
    // If set to "*", the pre-flight will allow whatever headers have been
    // requested. If set to a comma separated list of valid HTTP headers, the
    // pre-flight will return exactly this list as allowed headers. If set in
    // any other way, the result is unspecified.

    if (j.contains("access-control-allow-headers") &&
        j["access-control-allow-headers"].is_string()) {
      m_web_access_control_allow_headers =
        j["access-control-allow-headers"].get<std::string>();
    }

    // error-pages : ""
    // This option may be used to specify a directory for user defined error
    // pages. To specify a directory, make sure the name ends with a backslash
    // (Windows) or slash (Linux, MacOS, ...). The error pages may be specified
    // for an individual http status code (e.g., 404 - page requested by the
    // client not found), a group of http status codes (e.g., 4xx - all client
    // errors) or all errors. The corresponding error pages must be called
    // error404.ext, error4xx.ext or error.ext, whereas the file extension may
    // be one of the extensions specified for the index_files option. See the
    // Wikipedia page on HTTP status codes.
    // http://en.wikipedia.org/wiki/HTTP_status_code

    if (j.contains("error-pages") && j["error-pages"].is_string()) {
      m_web_error_pages = j["error-pages"].get<std::string>();
    }

    // tcp-nodelay : 0
    // Enable TCP_NODELAY socket option on client connections.
    //
    // If set the socket option will disable Nagle's algorithm on the connection
    // which means that packets will be sent as soon as possible instead of
    // waiting for a full buffer or timeout to occur.
    //
    // 0    Keep the default: Nagel's algorithm enabled
    // 1    Disable Nagel's algorithm for all sockets

    if (j.contains("tcp-nodelay") && j["tcp-nodelay"].is_number()) {
      m_web_tcp_nodelay = j["tcp-nodelay"].get<long>();
    }

    // static-file-cache-control : ""
    // Set the Cache-Control header of static files responses. The string value
    // will be used directly.
    //
    // E.g. this config:
    //
    // static_file_cache_control no-cache, max-age=31536000
    //
    // Will result in this header being added:
    //
    // Cache-Control: no-cache, max-age=31536000
    //
    // This will take precedence over the static_file_max_age option.

    if (j.contains("static-file-cache-control") &&
        j["static-file-cache-control"].is_string()) {
      m_web_static_file_cache_control =
        j["static-file-cache-control"].get<std::string>();
    }

    // static-file-max-age : 3600
    // Set the maximum time (in seconds) a cache may store a static files.
    //
    // This option will set the Cache-Control: max-age value for static files.
    // Dynamically generated content, i.e., content created by a script or
    // callback, must send cache control headers by themselves.
    //
    // A value >0 corresponds to a maximum allowed caching time in seconds. This
    // value should not exceed one year (RFC 2616, Section 14.21). A value of 0
    // will send "do not cache at all" headers for all static files. For values
    // <0 and values >31622400 (366 days), the behaviour is undefined.

    if (j.contains("static-file-max-age") &&
        j["static-file-max-age"].is_number()) {
      m_web_static_file_max_age = j["static-file-max-age"].get<long>();
    }

    // strict-transport-security-max_age : "",
    // Set the Strict-Transport-Security header, and set the max-age value. This
    // instructs web browsers to interact with the server only using HTTPS,
    // never by HTTP. If set, it will be sent for every request handled directly
    // by the server, except scripts (CGI, Lua, ..) and callbacks. They must
    // send HTTP headers on their own.
    //
    // The time is specified in seconds. If this configuration is not set, or
    // set to -1, no Strict-Transport-Security header will be sent. For values
    // <-1 and values >31622400, the behaviour is undefined.

    if (j.contains("strict-transport-security-max-age") &&
        j["strict-transport-security-max-age"].is_number()) {
      m_web_strict_transport_security_max_age =
        j["strict-transport-security-max-age"].get<long>();
    }

    // allow-sendfile-call : true
    // This option can be used to enable or disable the use of the Linux
    // sendfile system call. It is only available for Linux systems and only
    // affecting HTTP (not HTTPS) connections if throttle is not enabled. While
    // using the sendfile call will lead to a performance boost for HTTP
    // connections, this call may be broken for some file systems and some
    // operating system versions.

    if (j.contains("allow-sendfile-call") &&
        j["allow-sendfile-call"].is_boolean()) {
      m_web_allow_sendfile_call = j["allow-sendfile-call"].get<bool>();
    }

    // additional-header : ""
    // Send additional HTTP response header line for every request. The full
    // header line including key and value must be specified, excluding the
    // carriage return line feed.
    //
    // Example (used as command line option): -additional_header
    // "X-Frame-Options: SAMEORIGIN"
    //
    // This option can be specified multiple times. All specified header lines
    // will be sent.
    //
    // allow_index_script_resource no
    // Index scripts (like index.cgi or index.lua) may have script handled
    // resources.
    //
    // It this feature is activated, that /some/path/file.ext might be handled
    // by:
    //
    // /some/path/file.ext (with PATH_INFO='/', if ext = cgi)
    // /some/path/index.lua with mg.request_info.path_info='/file.ext'
    // /some/path/index.cgi with PATH_INFO='/file.ext'
    // /some/path/index.php with PATH_INFO='/file.ext'
    // /some/index.lua with mg.request_info.path_info=='/path/file.ext'
    // /some/index.cgi with PATH_INFO='/path/file.ext'
    // /some/index.php with PATH_INFO='/path/file.ext'
    // /index.lua with mg.request_info.path_info=='/some/path/file.ext'
    // /index.cgi with PATH_INFO='/some/path/file.ext'
    // /index.php with PATH_INFO='/some/path/file.ext'
    // Note: This example is valid, if the default configuration values for
    // index_files, cgi_pattern and lua_script_pattern are used, and the server
    // is built with CGI and Lua support enabled.
    //
    // If this feature is not activated, only the first file
    // (/some/path/file.cgi) will be accepted.
    //
    // Note: This parameter affects only index scripts. A path like
    // /here/script.cgi/handle/this.ext will call /here/script.cgi with
    // PATH_INFO='/handle/this.ext', no matter if this option is set to yes or
    // no.
    //
    // This feature can be used to completely hide the script extension from the
    // URL.

    if (j.contains("additional-header") && j["additional-header"].is_string()) {
      m_web_additional_header = j["additional-header"].get<std::string>();
    }

    // max-request-size : 16384
    // Size limit for HTTP request headers and header data returned from CGI
    // scripts, in Bytes. A buffer of the configured size is pre allocated for
    // every worker thread. max_request_size limits the HTTP header, including
    // query string and cookies, but it does not affect the HTTP body length.
    // The server has to read the entire header from a client or from a CGI
    // script, before it is able to process it. In case the header is longer
    // than max_request_size, the request is considered as invalid or as DoS
    // attack. The configuration value is approximate, the real limit might be a
    // few bytes off. The minimum is 1024 (1 kB).

    if (j.contains("max-request-size") && j["max-request-size"].is_number()) {
      m_web_max_request_size = j["max-request-size"].get<long>();
    }

    // allow-index-script-resource : false
    // Index scripts (like index.cgi or index.lua) may have script handled
    // resources.
    //
    // It this feature is activated, that /some/path/file.ext might be handled
    // by:
    //
    // /some/path/file.ext (with PATH_INFO='/', if ext = cgi)
    // /some/path/index.lua with mg.request_info.path_info='/file.ext'
    // /some/path/index.cgi with PATH_INFO='/file.ext'
    // /some/path/index.php with PATH_INFO='/file.ext'
    // /some/index.lua with mg.request_info.path_info=='/path/file.ext'
    // /some/index.cgi with PATH_INFO='/path/file.ext'
    // /some/index.php with PATH_INFO='/path/file.ext'
    // /index.lua with mg.request_info.path_info=='/some/path/file.ext'
    // /index.cgi with PATH_INFO='/some/path/file.ext'
    // /index.php with PATH_INFO='/some/path/file.ext'
    // Note: This example is valid, if the default configuration values for
    // index_files, cgi_pattern and lua_script_pattern are used, and the server
    // is built with CGI and Lua support enabled.
    //
    // If this feature is not activated, only the first file
    // (/some/path/file.cgi) will be accepted.
    //
    // Note: This parameter affects only index scripts. A path like
    // /here/script.cgi/handle/this.ext will call /here/script.cgi with
    // PATH_INFO='/handle/this.ext', no matter if this option is set to yes or
    // no.
    //
    // This feature can be used to completely hide the script extension from the
    // URL.

    if (j.contains("allow-index-script-resource") &&
        j["allow-index-script-resource"].is_boolean()) {
      m_web_allow_index_script_resource =
        j["allow-index-script-resource"].get<bool>();
    }

    // run_as_user : ""
    // Switch to given user credentials after startup. Usually, this option is
    // required when CivetWeb needs to bind on privileged ports on UNIX. To do
    // that, CivetWeb needs to be started as root. From a security point of
    // view, running as root is not advisable, therefore this option can be used
    // to drop privileges. Example:
    //
    // civetweb -listening_ports 80 -run_as_user webserver

    if (j.contains("run_as_user") && j["run_as_user"].is_string()) {
      m_web_run_as_user = j["run_as_user"].get<std::string>();
    }

    // case_sensitive : false
    // This option can be uset to enable case URLs for Windows servers. It is
    // only available for Windows systems. Windows file systems are not case
    // sensitive, but they still store the file name including case. If this
    // option is set to yes, the comparison for URIs and Windows file names will
    // be case sensitive.

    if (j.contains("case_sensitive") && j["run_as_user"].is_boolean()) {
      m_web_case_sensitive = j["case_sensitive"].get<bool>();
    }

    ///////////////////////////////////////////////////////////////////////
    //                                TLS
    ///////////////////////////////////////////////////////////////////////

    // TLS / SSL
    if (j.contains("tls") && j["tls"].is_object()) {

      json jj = j["tls"];

      // Certificate
      // Path to the SSL certificate file. This option is only required when at
      // least one of the listening\_ports is SSL. The file must be in PEM
      // format, and it must have both, private key and certificate, see for
      // example ssl_cert.pem A description how to create a certificate can be
      // found in doc/OpenSSL.md

      if (jj.contains("certificate")) {
        try {
          m_web_ssl_certificate = jj["certificate"].get<std::string>();
        }
        catch (const std::exception& ex) {
          spdlog::error(" Failed to read 'certificate' Error='{}'", ex.what());
        }
        catch (...) {
          spdlog::error(" Failed to read 'certificate' due to unknown error.");
        }
      }
      else {
        spdlog::debug(" Failed to read 'certificate' Defaults will be used.");
      }

      // certificate chain
      // Path to an SSL certificate chain file. As a default, the
      // ssl_certificate file is used.

      if (jj.contains("certificate-chain")) {
        try {
          m_web_ssl_certificate_chain =
            jj["certificate-chain"].get<std::string>();
        }
        catch (const std::exception& ex) {
          spdlog::error(" Failed to read 'certificate-chain' Error='{}'",
                        ex.what());
        }
        catch (...) {
          spdlog::error(
            " Failed to read 'certificate-chain' due to unknown error.");
        }
      }
      else {
        spdlog::debug(
          " Failed to read 'certificate-chain' Defaults will be used.");
      }

      // verify peer: false
      // Enable client's certificate verification by the server.

      if (jj.contains("verify-peer")) {
        try {
          m_web_ssl_verify_peer = jj["verify-peer"].get<bool>();
        }
        catch (const std::exception& ex) {
          spdlog::error(" Failed to read 'verify-peer' Error='{}'", ex.what());
        }
        catch (...) {
          spdlog::error(" Failed to read 'verify-peer' due to unknown error.");
        }
      }
      else {
        spdlog::debug(" Failed to read 'verify-peer' Defaults will be used.");
      }

      // CA Path
      // Name of a directory containing trusted CA certificates. Each file in
      // the directory must contain only a single CA certificate. The files must
      // be named by the subject name’s hash and an extension of “.0”. If there
      // is more than one certificate with the same subject name they should
      // have extensions ".0", ".1", ".2" and so on respectively.

      if (jj.contains("ca-path")) {
        try {
          m_web_ssl_ca_path = jj["ca-path"].get<std::string>();
        }
        catch (const std::exception& ex) {
          spdlog::error(" Failed to read 'ca-path' Error='{}'", ex.what());
        }
        catch (...) {
          spdlog::error(" Failed to read 'ca-path' due to unknown error.");
        }
      }
      else {
        spdlog::debug("  Failed to read 'ca-path' Defaults will be used.");
      }

      // CA File
      // Path to a .pem file containing trusted certificates. The file may
      // contain more than one certificate.

      if (jj.contains("ca-file")) {
        try {
          m_web_ssl_ca_file = jj["ca-file"].get<std::string>();
        }
        catch (const std::exception& ex) {
          spdlog::error(" Failed to read 'ca-file' Error='{}'", ex.what());
        }
        catch (...) {
          spdlog::error(" Failed to read 'ca-file' due to unknown error.");
        }
      }
      else {
        spdlog::debug("  Failed to read 'ca-file' Defaults will be used.");
      }

      // Verify depth: 9
      // Sets maximum depth of certificate chain. If client's certificate chain
      // is longer than the depth set here connection is refused.

      if (jj.contains("verify-depth")) {
        try {
          m_web_ssl_verify_depth = jj["verify-depth"].get<uint16_t>();
        }
        catch (const std::exception& ex) {
          spdlog::error(" Failed to read 'verify-depth' Error='{}'", ex.what());
        }
        catch (...) {
          spdlog::error(" Failed to read 'verify-depth' due to unknown error.");
        }
      }
      else {
        spdlog::debug(" Failed to read 'verify-depth' Defaults will be used.");
      }

      // Default verify paths : true
      // Loads default trusted certificates locations set at openssl compile
      // time.

      if (jj.contains("default-verify-paths")) {
        try {
          m_web_ssl_default_verify_paths =
            jj["default-verify-paths"].get<bool>();
        }
        catch (const std::exception& ex) {
          spdlog::error("Failed to read 'default-verify-paths' Error='{}'",
                        ex.what());
        }
        catch (...) {
          spdlog::error(
            "Failed to read 'default-verify-paths' due to unknown error.");
        }
      }
      else {
        spdlog::debug(
          " Failed to read 'default-verify-paths' Defaults will be used.");
      }

      // Chiper list
      // List of ciphers to present to the client. Entries should be separated
      // by colons, commas or spaces.
      //
      // ALL           All available ciphers
      // ALL:!eNULL    All ciphers excluding NULL ciphers
      // AES128:!MD5   AES 128 with digests other than MD5
      // See this entry in OpenSSL documentation for full list of options and
      // additional examples.

      if (jj.contains("cipher-list")) {
        try {
          m_web_ssl_cipher_list = jj["cipher-list"].get<std::string>();
        }
        catch (const std::exception& ex) {
          spdlog::error("Failed to read 'cipher-list' Error='{}'", ex.what());
        }
        catch (...) {
          spdlog::error("Failed to read 'cipher-list' due to unknown error.");
        }
      }
      else {
        spdlog::debug(" Failed to read 'cipher-list' Defaults will be used.");
      }

      // Protocol version
      // Sets the minimal accepted version of SSL/TLS protocol according to the
      // table:
      //
      // Protocols	                            Value
      // SSL2+SSL3+TLS1.0+TLS1.1+TLS1.2+TLS1.3	0
      // SSL3+TLS1.0+TLS1.1+TLS1.2+TLS1.3	        1
      // TLS1.0+TLS1.1+TLS1.2+TLS1.3	            2
      // TLS1.1+TLS1.2+TLS1.3	                    3
      // TLS1.2+TLS1.3	                        4
      // TLS1.3	                                5
      //
      // TLS version 1.3 is only available if you are using an up-to-date TLS
      // libary. The default setting has been changed from 0 to 4 in
      // CivetWeb 1.14.

      if (jj.contains("protocol-version")) {
        try {
          m_web_ssl_protocol_version = jj["protocol-version"].get<uint16_t>();
        }
        catch (const std::exception& ex) {
          spdlog::error("Failed to read 'protocol-version' Error='{}'",
                        ex.what());
        }
        catch (...) {
          spdlog::error(
            "Failed to read 'protocol-version' due to unknown error.");
        }
      }
      else {
        spdlog::debug(
          " Failed to read 'protocol-version' Defaults will be used.");
      }

      // Short trust: false
      // Enables the use of short lived certificates. This will allow for the
      // certificates and keys specified in ssl_certificate, ssl_ca_file and
      // ssl_ca_path to be exchanged and reloaded while the server is running.
      //
      // In an automated environment it is advised to first write the new pem
      // file to a different filename and then to rename it to the configured
      // pem file name to increase performance while swapping the certificate.
      //
      // Disk IO performance can be improved when keeping the certificates and
      // keys stored on a tmpfs (linux) on a system with very high throughput.

      if (jj.contains("short-trust")) {
        try {
          m_web_ssl_short_trust = jj["short-trust"].get<bool>();
        }
        catch (const std::exception& ex) {
          spdlog::error("Failed to read 'short-trust' Error='{}'", ex.what());
        }
        catch (...) {
          spdlog::error("Failed to read 'short-trust' due to unknown error.");
        }
      }
      else {
        spdlog::debug(" Failed to read 'short-trust' Defaults will be used.");
      }

      // Allow caching of SSL/TLS sessions, so HTTPS connection from the same
      // client to the same server can be established faster. A configuration
      // value >0 activates session caching. The configuration value is the
      // maximum lifetime of a cached session in seconds. The default is to
      // deactivated session caching.

      // ssl_cache_timeout: -1
      if (jj.contains("cache-timeout")) {
        try {
          m_web_ssl_cache_timeout = jj["ssl-cache-timeout"].get<long>();
        }
        catch (const std::exception& ex) {
          spdlog::error("Failed to read 'ssl-cache-timeout' Error='{}'",
                        ex.what());
        }
        catch (...) {
          spdlog::error(
            "Failed to read 'ssl-cache-timeout' due to unknown error.");
        }
      }
      else {
        spdlog::debug(
          " Failed to read 'ssl-cache-timeout' Defaults will be used.");
      }

    } // TLS

    // CGI
    if (j.contains("cgi") && j["cgi"].is_object()) {

      json jj = j["cgi"];

      // cgi-interpreter
      if (jj.contains("cgi-interpreter") && jj["cgi-interpreter"].is_string()) {
        m_web_cgi_interpreter = jj["cgi-interpreter"].get<std::string>();
      }

      // cgi-patterns
      if (jj.contains("cgi-patterns") && jj["cgi-patterns"].is_string()) {
        m_web_cgi_patterns = jj["cgi-patterns"].get<std::string>();
      }

      // cgi-environment
      if (jj.contains("cgi-environment") && jj["cgi-environment"].is_string()) {
        m_web_cgi_environment = jj["cgi-environment"].get<std::string>();
      }

    } // CGI

    // Duktape
    if (j.contains("duktape") && j["duktape"].is_object()) {

      json jj = j["duktape"];

      // duktape-script-patterns
      if (jj.contains("duktape-script-patterns") &&
          jj["duktape-script-patterns"].is_string()) {
        m_web_duktape_script_patterns =
          jj["duktape-script-patterns"].get<std::string>();
      }
    } // Duktape

    // lua
    if (j.contains("lua") && j["lua"].is_object()) {

      json jj = j["lua"];

      // lua-preload-file
      if (jj.contains("lua-preload-file") &&
          jj["lua-preload-file"].is_string()) {
        m_web_lua_preload_file = jj["lua-preload-file"].get<std::string>();
      }
      // lua-script-patterns
      if (jj.contains("lua-script-patterns") &&
          jj["lua-script-patterns"].is_string()) {
        m_web_lua_script_patterns =
          jj["lua-script-patterns"].get<std::string>();
      }
      // lua-server-page_patterns
      if (jj.contains("lua-server-page_patterns") &&
          jj["lua-server-page_patterns"].is_string()) {
        m_web_lua_server_page_patterns =
          jj["lua-server-page_patterns"].get<std::string>();
      }
      // lua-websocket-patterns
      if (jj.contains("lua-websocket-patterns") &&
          jj["lua-websocket-patterns"].is_string()) {
        m_web_lua_websocket_patterns =
          jj["lua-websocket-patterns"].get<std::string>();
      }
      // lua-background-script
      if (jj.contains("lua-background-script") &&
          jj["lua-background-script"].is_string()) {
        m_web_lua_background_script =
          jj["lua-background-script"].get<std::string>();
      }
      // lua-background-script-params
      if (jj.contains("lua-background-script-params") &&
          jj["lua-background-script-params"].is_string()) {
        m_web_lua_background_script_params =
          jj["lua-background-script-params"].get<std::string>();
      }
    }

  } // WEB - server

  //*************************************************************************
  //                             REST API
  //*************************************************************************

  if (m_j_config.contains("restapi") && m_j_config["restapi"].is_object()) {

    json j = m_j_config["restapi"];

    // enable
    if (j.contains("enable") && j["enable"].is_boolean()) {
      m_bEnableRestApi = j["enable"].get<bool>();
    }

  } // restapi

  //*************************************************************************
  //                             Websockets
  //*************************************************************************

  if (m_j_config.contains("websocket") && m_j_config["websocket"].is_object()) {

    json j = m_j_config["websocket"];

    // enable
    if (j.contains("enable") && j["enable"].is_boolean()) {
      m_bEnableWebsockets = j["enable"].get<bool>();
    }

    // websocket-root : "",
    if (j.contains("websocket-root") && j["websocket-root"].is_string()) {
      m_websocket_document_root = j["websocket-root"].get<std::string>();
    }

    // websocket-timeout-ms : 2000,
    if (j.contains("websocket-timeout-ms") &&
        j["websocket-timeout-ms"].is_number()) {
      m_websocket_timeout_ms = j["websocket-timeout-ms"].get<long>();
    }

    // enable-websocket-ping-pong : false,
    if (j.contains("enable-websocket-ping-pong") &&
        j["enable-websocket-ping-pong"].is_boolean()) {
      bEnable_websocket_ping_pong = j["enable-websocket-ping-pong"].get<bool>();
    }

  } // websocket

  return true;
}

// int depth_hlo_parser = 0;

// void
// startHLOParser(void* data, const char* name, const char** attr)
// {
//     CHLO* pObj = (CHLO*)data;
//     if (NULL == pObj)
//         return;

//     if ((0 == strcmp(name, "vscp-cmd")) && (0 == depth_setup_parser)) {

//         for (int i = 0; attr[i]; i += 2) {

//             std::string attribute = attr[i + 1];
//             vscp_trim(attribute);

//             if (0 == strcasecmp(attr[i], "op")) {
//                 if (!attribute.empty()) {
//                     pObj->m_op = vscp_readStringValue(attribute);
//                     vscp_makeUpper(attribute);
//                     if (attribute == "VSCP-NOOP") {
//                         pObj->m_op = HLO_OP_NOOP;
//                     } else if (attribute == "VSCP-READVAR") {
//                         pObj->m_op = HLO_OP_READ_VAR;
//                     } else if (attribute == "VSCP-WRITEVAR") {
//                         pObj->m_op = HLO_OP_WRITE_VAR;
//                     } else if (attribute == "VSCP-LOAD") {
//                         pObj->m_op = HLO_OP_LOAD;
//                     } else if (attribute == "VSCP-SAVE") {
//                         pObj->m_op = HLO_OP_SAVE;
//                     } else if (attribute == "CALCULATE") {
//                         pObj->m_op = HLO_OP_SAVE;
//                     } else {
//                         pObj->m_op = HLO_OP_UNKNOWN;
//                     }
//                 }
//             } else if (0 == strcasecmp(attr[i], "name")) {
//                 if (!attribute.empty()) {
//                     vscp_makeUpper(attribute);
//                     pObj->m_name = attribute;
//                 }
//             } else if (0 == strcasecmp(attr[i], "type")) {
//                 if (!attribute.empty()) {
//                     pObj->m_varType = vscp_readStringValue(attribute);
//                 }
//             } else if (0 == strcasecmp(attr[i], "value")) {
//                 if (!attribute.empty()) {
//                     if (vscp_base64_std_decode(attribute)) {
//                         pObj->m_value = attribute;
//                     }
//                 }
//             } else if (0 == strcasecmp(attr[i], "full")) {
//                 if (!attribute.empty()) {
//                     vscp_makeUpper(attribute);
//                     if ("TRUE" == attribute) {
//                         pObj->m_bFull = true;
//                     } else {
//                         pObj->m_bFull = false;
//                     }
//                 }
//             }
//         }
//     }

//     depth_hlo_parser++;
// }

// void
// endHLOParser(void* data, const char* name)
// {
//     depth_hlo_parser--;
// }

// ----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// parseHLO
//

// bool
// CWebObj::parseHLO(uint16_t size, uint8_t* inbuf, CHLO* phlo)
// {
//     // Check pointers
//     if (NULL == inbuf) {
//         spdlog::get("logger")->error(
//           "HLO parser: HLO in-buffer pointer is NULL.");
//         return false;
//     }

//     if (NULL == phlo) {
//         spdlog::get("logger")->error(
//                "HLO parser: HLO obj pointer is NULL.");
//         return false;
//     }

//     if (!size) {
//         spdlog::get("logger")->error(
//                "HLO parser: HLO buffer size is zero.");
//         return false;
//     }

//     XML_Parser xmlParser = XML_ParserCreate("UTF-8");
//     XML_SetUserData(xmlParser, this);
//     XML_SetElementHandler(xmlParser, startHLOParser, endHLOParser);

//     void* buf = XML_GetBuffer(xmlParser, XML_BUFF_SIZE);

//     // Copy in the HLO object
//     memcpy(buf, inbuf, size);

//     if (!XML_ParseBuffer(xmlParser, size, size == 0)) {
//         spdlog::get("logger")->error( "Failed parse XML setup.");
//         XML_ParserFree(xmlParser);
//         return false;
//     }

//     XML_ParserFree(xmlParser);

//     return true;
// }

// ----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// loadConfiguration
//

// bool
// CWebObj::doLoadConfig(void)
// {
//     FILE* fp;

//     fp = fopen(m_path.c_str(), "r");
//     if (NULL == fp) {
//         spdlog::get("logger")->error(
//                "Failed to open configuration file [{}]",
//                m_path.c_str());
//         return false;
//     }

//     XML_Parser xmlParser = XML_ParserCreate("UTF-8");
//     XML_SetUserData(xmlParser, this);
//     XML_SetElementHandler(xmlParser, startSetupParser, endSetupParser);

//     void* buf = XML_GetBuffer(xmlParser, XML_BUFF_SIZE);

//     size_t file_size = 0;
//     file_size = fread(buf, sizeof(char), XML_BUFF_SIZE, fp);

//     if (!XML_ParseBuffer(xmlParser, file_size, file_size == 0)) {
//         spdlog::get("logger")->error( "Failed parse XML setup.");
//         XML_ParserFree(xmlParser);
//         return false;
//     }

//     XML_ParserFree(xmlParser);

//     return true;
// }

#define TEMPLATE_SAVE_CONFIG                                                   \
  "<setup "                                                                    \
  " host=\"%s\" "                                                              \
  " port=\"%d\" "                                                              \
  " user=\"%s\" "                                                              \
  " password=\"%s\" "                                                          \
  " rxfilter=\"%s\" "                                                          \
  " rxmask=\"%s\" "                                                            \
  " txfilter=\"%s\" "                                                          \
  " txmask=\"%s\" "                                                            \
  " responsetimeout=\"%lu\" "                                                  \
  "/>"

///////////////////////////////////////////////////////////////////////////////
// saveConfiguration
//

// bool
// CWebObj::doSaveConfig(void)
// {
//     char buf[2048]; // Working buffer

//     std::string strRxFilter, strRxMask;
//     std::string strTxFilter, strTxMask;
//     vscp_writeFilterToString( strRxFilter, &m_rxfilter );
//     vscp_writeFilterToString( strRxMask, &m_rxfilter );
//     vscp_writeFilterToString( strTxFilter, &m_txfilter );
//     vscp_writeFilterToString( strTxMask, &m_txfilter );

//     sprintf( buf,
//         TEMPLATE_SAVE_CONFIG,
//         m_hostRemote.c_str(),
//         m_portRemote,
//         m_usernameRemote.c_str(),
//         m_passwordRemote.c_str(),
//         strRxFilter.c_str(),
//         strRxMask.c_str(),
//         strTxFilter.c_str(),
//         strTxMask.c_str(),
//         (long unsigned int)m_responseTimeout );

//     FILE* fp;

//     fp = fopen(m_path.c_str(), "w");
//     if (NULL == fp) {
//         spdlog::get("logger")->error(
//                "Failed to open configuration file [{}] for write",
//                m_path.c_str());
//         return false;
//     }

//     if ( strlen(buf) != fwrite( buf, sizeof(char), strlen(buf), fp ) ) {
//         spdlog::get("logger")->error(
//                "Failed to write configuration file [{}] ",
//                m_path.c_str());
//         fclose (fp);
//         return false;
//     }

//     fclose(fp);
//     return true;
// }

///////////////////////////////////////////////////////////////////////////////
// handleHLO
//

// bool
// CWebObj::handleHLO(vscpEvent* pEvent)
// {
//     char buf[512]; // Working buffer
//     vscpEventEx ex;

//     // Check pointers
//     if (NULL == pEvent) {
//         spdlog::get("logger")->error(
//                "HLO handler: NULL event pointer.");
//         return false;
//     }

//     CHLO hlo;
//     if (!parseHLO(pEvent->sizeData, pEvent->pdata, &hlo)) {
//         spdlog::get("logger")->error( "Failed to parse HLO.");
//         return false;
//     }

//     ex.obid = 0;
//     ex.head = 0;
//     ex.timestamp = vscp_makeTimeStamp();
//     vscp_setEventExToNow(&ex); // Set time to current time
//     ex.vscp_class = VSCP_CLASS2_PROTOCOL;
//     ex.vscp_type = VSCP2_TYPE_HLO_COMMAND;
//     m_guid.writeGUID(ex.GUID);

//     switch (hlo.m_op) {

//         case HLO_OP_NOOP:
//             // Send positive response
//             sprintf(buf,
//                     HLO_CMD_REPLY_TEMPLATE,
//                     "noop",
//                     "OK",
//                     "NOOP commaned executed correctly.");

//             memset(ex.data, 0, sizeof(ex.data));
//             ex.sizeData = strlen(buf);
//             memcpy(ex.data, buf, ex.sizeData);

//             // Put event in receive queue
//             return eventExToReceiveQueue(ex);

//         case HLO_OP_READ_VAR:
//             if ("REMOTE-HOST" == hlo.m_name) {
//                 sprintf(buf,
//                         HLO_READ_VAR_REPLY_TEMPLATE,
//                         "remote-host",
//                         "OK",
//                         VSCP_REMOTE_VARIABLE_CODE_STRING,
//                         vscp_convertToBase64(m_hostRemote).c_str());
//             } else if ("REMOTE-PORT" == hlo.m_name) {
//                 char ibuf[80];
//                 sprintf(ibuf, "%d", m_portRemote);
//                 sprintf(buf,
//                         HLO_READ_VAR_REPLY_TEMPLATE,
//                         "remote-port",
//                         "OK",
//                         VSCP_REMOTE_VARIABLE_CODE_INTEGER,
//                         vscp_convertToBase64(ibuf).c_str());
//             } else if ("REMOTE-USER" == hlo.m_name) {
//                 sprintf(buf,
//                         HLO_READ_VAR_REPLY_TEMPLATE,
//                         "remote-user",
//                         "OK",
//                         VSCP_REMOTE_VARIABLE_CODE_INTEGER,
//                         vscp_convertToBase64(m_usernameRemote).c_str());
//             } else if ("REMOTE-PASSWORD" == hlo.m_name) {
//                 sprintf(buf,
//                         HLO_READ_VAR_REPLY_TEMPLATE,
//                         "remote-password",
//                         "OK",
//                         VSCP_REMOTE_VARIABLE_CODE_INTEGER,
//                         vscp_convertToBase64(m_passwordRemote).c_str());
//             } else if ("TIMEOUT-RESPONSE" == hlo.m_name) {
//                 char ibuf[80];
//                 sprintf(ibuf, "%lu", (long unsigned int)m_responseTimeout);
//                 sprintf(buf,
//                         HLO_READ_VAR_REPLY_TEMPLATE,
//                         "timeout-response",
//                         "OK",
//                         VSCP_REMOTE_VARIABLE_CODE_LONG,
//                         vscp_convertToBase64(ibuf).c_str());
//             }
//             break;

//         case HLO_OP_WRITE_VAR:
//             if ("REMOTE-HOST" == hlo.m_name) {
//                 if (VSCP_REMOTE_VARIABLE_CODE_STRING != hlo.m_varType) {
//                     // Wrong variable type
//                     sprintf(buf,
//                             HLO_READ_VAR_ERR_REPLY_TEMPLATE,
//                             "remote-host",
//                             ERR_VARIABLE_WRONG_TYPE,
//                             "Variable type should be string.");
//                 } else {
//                     m_hostRemote = hlo.m_value;
//                     sprintf(buf,
//                             HLO_READ_VAR_REPLY_TEMPLATE,
//                             "enable-sunrise",
//                             "OK",
//                             VSCP_REMOTE_VARIABLE_CODE_STRING,
//                             vscp_convertToBase64(m_hostRemote).c_str());
//                 }
//             } else if ("REMOTE-PORT" == hlo.m_name) {
//                 if (VSCP_REMOTE_VARIABLE_CODE_INTEGER != hlo.m_varType) {
//                     // Wrong variable type
//                     sprintf(buf,
//                             HLO_READ_VAR_ERR_REPLY_TEMPLATE,
//                             "remote-port",
//                             ERR_VARIABLE_WRONG_TYPE,
//                             "Variable type should be integer.");
//                 } else {
//                     m_portRemote = vscp_readStringValue(hlo.m_value);
//                     char ibuf[80];
//                     sprintf(ibuf, "%d", m_portRemote);
//                     sprintf(buf,
//                             HLO_READ_VAR_REPLY_TEMPLATE,
//                             "remote-port",
//                             "OK",
//                             VSCP_REMOTE_VARIABLE_CODE_INTEGER,
//                             vscp_convertToBase64(ibuf).c_str());
//                 }
//             } else if ("REMOTE-USER" == hlo.m_name) {
//                 if (VSCP_REMOTE_VARIABLE_CODE_STRING != hlo.m_varType) {
//                     // Wrong variable type
//                     sprintf(buf,
//                             HLO_READ_VAR_ERR_REPLY_TEMPLATE,
//                             "remote-port",
//                             ERR_VARIABLE_WRONG_TYPE,
//                             "Variable type should be string.");
//                 } else {
//                     m_usernameRemote = hlo.m_value;
//                     sprintf(buf,
//                             HLO_READ_VAR_REPLY_TEMPLATE,
//                             "remote-user",
//                             "OK",
//                             VSCP_REMOTE_VARIABLE_CODE_STRING,
//                             vscp_convertToBase64(m_usernameRemote).c_str());
//                 }
//             } else if ("REMOTE-PASSWORD" == hlo.m_name) {
//                 if (VSCP_REMOTE_VARIABLE_CODE_STRING != hlo.m_varType) {
//                     // Wrong variable type
//                     sprintf(buf,
//                             HLO_READ_VAR_ERR_REPLY_TEMPLATE,
//                             "remote-password",
//                             ERR_VARIABLE_WRONG_TYPE,
//                             "Variable type should be string.");
//                 } else {
//                     m_passwordRemote = hlo.m_value;
//                     sprintf(buf,
//                             HLO_READ_VAR_REPLY_TEMPLATE,
//                             "remote-password!",
//                             "OK",
//                             VSCP_REMOTE_VARIABLE_CODE_STRING,
//                             vscp_convertToBase64(m_passwordRemote).c_str());
//                 }
//             } else if ("TIMEOUT-RESPONSE¤" == hlo.m_name) {
//                 if (VSCP_REMOTE_VARIABLE_CODE_INTEGER != hlo.m_varType) {
//                     // Wrong variable type
//                     sprintf(buf,
//                             HLO_READ_VAR_ERR_REPLY_TEMPLATE,
//                             "timeout-response",
//                             ERR_VARIABLE_WRONG_TYPE,
//                             "Variable type should be uint32.");
//                 } else {
//                     m_responseTimeout = vscp_readStringValue(hlo.m_value);
//                     char ibuf[80];
//                     sprintf(ibuf, "%lu", (long unsigned
//                     int)m_responseTimeout); sprintf(buf,
//                             HLO_READ_VAR_REPLY_TEMPLATE,
//                             "timeout-response",
//                             "OK",
//                             VSCP_REMOTE_VARIABLE_CODE_UINT32,
//                             vscp_convertToBase64(ibuf).c_str());
//                 }
//             }
//             break;

//         // Save configuration
//         case HLO_OP_SAVE:
//             doSaveConfig();
//             break;

//         // Load configuration
//         case HLO_OP_LOAD:
//             doLoadConfig();
//             break;

//         // Connect tyo remote host
//         case HLO_OP_LOCAL_CONNECT:
//             break;

//         // Disconnect from remote host
//         case HLO_OP_LOCAL_DISCONNECT:
//             break;

//         default:
//             break;
//     };

//     return true;
// }

///////////////////////////////////////////////////////////////////////////////
// eventExToReceiveQueue
//

bool
CWebObj::eventExToReceiveQueue(vscpEventEx& ex)
{
  vscpEvent* pev = new vscpEvent();
  if (!vscp_convertEventExToEvent(pev, &ex)) {
    spdlog::get("logger")->error("Failed to convert event from ex to ev.");
    vscp_deleteEvent(pev);
    return false;
  }
  if (NULL != pev) {
    if (vscp_doLevel2Filter(pev, &m_filterIn)) {
      pthread_mutex_lock(&m_mutexReceiveQueue);
      m_receiveList.push_back(pev);
      sem_post(&m_semReceiveQueue);
      pthread_mutex_unlock(&m_mutexReceiveQueue);
    }
    else {
      vscp_deleteEvent(pev);
    }
  }
  else {
    spdlog::get("logger")->error("Unable to allocate event storage.");
  }
  return true;
}

//////////////////////////////////////////////////////////////////////
// addEvent2SendQueue
//

bool
CWebObj::addEvent2SendQueue(const vscpEvent* pEvent)
{
  pthread_mutex_lock(&m_mutexSendQueue);
  m_sendList.push_back((vscpEvent*)pEvent);
  sem_post(&m_semSendQueue);
  pthread_mutex_lock(&m_mutexSendQueue);
  return true;
}

//////////////////////////////////////////////////////////////////////
// Send worker thread
//

void*
workerThreadSend(void* pData)
{
  bool bRemoteConnectionLost = false;

  CWebObj* pObj = (CWebObj*)pData;
  if (NULL == pObj) {
    return NULL;
  }

retry_send_connect:

  // // Open remote interface
  // if (VSCP_ERROR_SUCCESS !=
  //     pObj->m_srvRemoteSend.doCmdOpen(pObj->m_hostRemote,
  //                                 pObj->m_portRemote,
  //                                 pObj->m_usernameRemote,
  //                                 pObj->m_passwordRemote)) {
  //     spdlog::get("logger")->error(
  //            "{} {} ",
  //            VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
  //            (const char*)"Error while opening remote VSCP TCP/IP "
  //                         "interface. Terminating!");

  //     // Give the server some time to become active
  //     for (int loopcnt = 0; loopcnt < VSCP_TCPIPLINK_DEFAULT_RECONNECT_TIME;
  //          loopcnt++) {
  //         sleep(1);
  //         if (pObj->m_bQuit)
  //             return NULL;
  //     }

  //     goto retry_send_connect;
  // }

  // spdlog::get("logger")->error(
  //        "{} {} ",
  //        VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
  //        (const char*)"Connect to remote VSCP TCP/IP interface [SEND].");

  // // Find the channel id
  // pObj->m_srvRemoteSend.doCmdGetChannelID(&pObj->txChannelID);

  // while (!pObj->m_bQuit) {

  //     // Make sure the remote connection is up
  //     if (!pObj->m_srvRemoteSend.isConnected()) {

  //         if (!bRemoteConnectionLost) {
  //             bRemoteConnectionLost = true;
  //             pObj->m_srvRemoteSend.doCmdClose();
  //             spdlog::get("logger")->error(
  //                    "{} {} ",
  //                    VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
  //                    (const char*)"Lost connection to remote host [SEND].");
  //         }

  //         // Wait before we try to connect again
  //         sleep(VSCP_TCPIPLINK_DEFAULT_RECONNECT_TIME);

  //         if (VSCP_ERROR_SUCCESS !=
  //             pObj->m_srvRemoteSend.doCmdOpen(pObj->m_hostRemote,
  //                                         pObj->m_portRemote,
  //                                         pObj->m_usernameRemote,
  //                                         pObj->m_passwordRemote)) {
  //             spdlog::get("logger")->error(
  //                    "{} {} ",
  //                    VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
  //                    (const char*)"Reconnected to remote host [SEND].");

  //             // Find the channel id
  //             pObj->m_srvRemoteSend.doCmdGetChannelID(&pObj->txChannelID);

  //             bRemoteConnectionLost = false;
  //         }

  //         continue;
  //     }

  //     if ((-1 == vscp_sem_wait(&pObj->m_semSendQueue, 500)) &&
  //         errno == ETIMEDOUT) {
  //         continue;
  //     }

  //     // Check if there is event(s) to send
  //     if (pObj->m_sendList.size()) {

  //         // Yes there are data to send
  //         pthread_mutex_lock(&pObj->m_mutexSendQueue);
  //         vscpEvent* pEvent = pObj->m_sendList.front();
  //         // Check if event should be filtered away
  //         if (!vscp_doLevel2Filter(pEvent, &pObj->m_txfilter)) {
  //             pthread_mutex_unlock(&pObj->m_mutexSendQueue);
  //             continue;
  //         }
  //         pObj->m_sendList.pop_front();
  //         pthread_mutex_unlock(&pObj->m_mutexSendQueue);

  //         // Only HLO object event is of interst to us
  //         if ((VSCP_CLASS2_PROTOCOL == pEvent->vscp_class) &&
  //             (VSCP2_TYPE_HLO_COMMAND == pEvent->vscp_type)) {
  //             pObj->handleHLO(pEvent);
  //         }

  //         if (NULL == pEvent)
  //             continue;

  //         // Yes there are data to send
  //         // Send it out to the remote server

  //         pObj->m_srvRemoteSend.doCmdSend(pEvent);
  //         vscp_deleteEvent_v2(&pEvent);
  //     }
  // }

  // // Close the channel
  // pObj->m_srvRemoteSend.doCmdClose();

  // spdlog::get("logger")->error(
  //        "{} {} ",
  //        VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
  //        (const char*)"Disconnect from remote VSCP TCP/IP interface
  //        [SEND].");

  return NULL;
}

//////////////////////////////////////////////////////////////////////
//                Workerthread Receive - CWrkReceiveTread
//////////////////////////////////////////////////////////////////////

void*
workerThreadReceive(void* pData)
{
  bool bRemoteConnectionLost             = false;
  __attribute__((unused)) bool bActivity = false;

  CWebObj* pObj = (CWebObj*)pData;
  if (NULL == pObj)
    return NULL;

retry_receive_connect:

  // if (pObj->m_bDebug) {
  //     printf("Open receive channel host = %s port = %d\n",
  //             pObj->m_hostRemote.c_str(),
  //             pObj->m_portRemote);
  // }

  // // Open remote interface
  // if (VSCP_ERROR_SUCCESS !=
  //     pObj->m_srvRemoteReceive.doCmdOpen(pObj->m_hostRemote,
  //                                         pObj->m_portRemote,
  //                                         pObj->m_usernameRemote,
  //                                         pObj->m_passwordRemote)) {
  //     spdlog::get("logger")->error(
  //            "{} {} ",
  //            VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
  //            (const char*)"Error while opening remote VSCP TCP/IP "
  //                         "interface. Terminating!");

  //     // Give the server some time to become active
  //     for (int loopcnt = 0; loopcnt < VSCP_TCPIPLINK_DEFAULT_RECONNECT_TIME;
  //          loopcnt++) {
  //         sleep(1);
  //         if (pObj->m_bQuit)
  //             return NULL;
  //     }

  //     goto retry_receive_connect;
  // }

  // spdlog::get("logger")->error(
  //        "{} {} ",
  //        VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
  //        (const char*)"Connect to remote VSCP TCP/IP interface [RECEIVE].");

  // // Set receive filter
  // if (VSCP_ERROR_SUCCESS !=
  //     pObj->m_srvRemoteReceive.doCmdFilter(&pObj->m_rxfilter)) {
  //     spdlog::get("logger")->error(
  //            "{} {} ",
  //            VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
  //            (const char*)"Failed to set receiving filter.");
  // }

  // // Enter the receive loop
  // pObj->m_srvRemoteReceive.doCmdEnterReceiveLoop();

  // __attribute__((unused)) vscpEventEx eventEx;
  // while (!pObj->m_bQuit) {

  //     // Make sure the remote connection is up
  //     if (!pObj->m_srvRemoteReceive.isConnected() ||
  //         ((vscp_getMsTimeStamp() -
  //         pObj->m_srvRemoteReceive.getlastResponseTime()) >
  //          (VSCP_TCPIPLINK_DEFAULT_RECONNECT_TIME * 1000))) {

  //         if (!bRemoteConnectionLost) {

  //             bRemoteConnectionLost = true;
  //             pObj->m_srvRemoteReceive.doCmdClose();
  //             spdlog::get("logger")->error( "{} {} ",
  //             VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
  //                         (const char*)"Lost connection to remote host
  //                         [Receive].");
  //         }

  //         // Wait before we try to connect again
  //         sleep(VSCP_TCPIPLINK_DEFAULT_RECONNECT_TIME);

  //         if (VSCP_ERROR_SUCCESS !=
  //             pObj->m_srvRemoteReceive.doCmdOpen(pObj->m_hostRemote,
  //                                                 pObj->m_portRemote,
  //                                                 pObj->m_usernameRemote,
  //                                                 pObj->m_passwordRemote)) {
  //             spdlog::get("logger")->error(
  //                    "{} {} ",
  //                    VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
  //                    (const char*)"Reconnected to remote host [Receive].");
  //             bRemoteConnectionLost = false;
  //         }

  //         // Enter the receive loop
  //         pObj->m_srvRemoteReceive.doCmdEnterReceiveLoop();

  //         continue;
  //     }

  //     // Check if remote server has something to send to us
  //     vscpEvent* pEvent = new vscpEvent;
  //     if (NULL != pEvent) {

  //         pEvent->sizeData = 0;
  //         pEvent->pdata = NULL;

  //         if (CANAL_ERROR_SUCCESS ==
  //             pObj->m_srvRemoteReceive.doCmdBlockingReceive(pEvent)) {

  //             // Filter is handled at server side. We check so we don't
  //             // receive things we send ourself.
  //             if (pObj->txChannelID != pEvent->obid) {
  //                 pthread_mutex_lock(&pObj->m_mutexReceiveQueue);
  //                 pObj->m_receiveList.push_back(pEvent);
  //                 sem_post(&pObj->m_semReceiveQueue);
  //                 pthread_mutex_unlock(&pObj->m_mutexReceiveQueue);
  //             } else {
  //                 vscp_deleteEvent(pEvent);
  //             }

  //         } else {
  //             vscp_deleteEvent(pEvent);
  //         }
  //     }
  // }

  // // Close the channel
  // pObj->m_srvRemoteReceive.doCmdClose();

  // spdlog::get("logger")->error("{} {} ",
  //   VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
  //   (const char*)"Disconnect from remote VSCP TCP/IP interface [RECEIVE].");

  return NULL;
}
