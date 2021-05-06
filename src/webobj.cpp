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
#include <websrv.h>

#include "webobj.h"

#include <json.hpp>  // Needs C++11  -std=c++11
#include <mustache.hpp>

#include <spdlog/spdlog.h>
#include <spdlog/async.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include <iostream>
#include <fstream>      
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
    m_bDebug = false;
    m_bWriteEnable = false;
    m_bQuit = false;

    vscp_clearVSCPFilter(&m_filterIn); // Accept all events
    vscp_clearVSCPFilter(&m_filterOut); // Send all events
    //m_responseTimeout = TCPIP_DEFAULT_INNER_RESPONSE_TIMEOUT;

    sem_init(&m_semSendQueue, 0, 0);
    sem_init(&m_semReceiveQueue, 0, 0);

    pthread_mutex_init(&m_mutexSendQueue, NULL);
    pthread_mutex_init(&m_mutexReceiveQueue, NULL);
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
}

//////////////////////////////////////////////////////////////////////
// sendEvent
//

bool CWebObj::sendEvent(vscpEventEx *pex)
{
    return true;
}

//////////////////////////////////////////////////////////////////////
// sendEvent
//

bool CWebObj::sendEvent(vscpEvent *pev)
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
        spdlog::get("logger")->error(
               "[vscpl2drv-websrv] Failed to load configuration file [%s]",
               path.c_str());
    }

    // Start the web server
    try {
        start_webserver();
    }
    catch (...) {
        spdlog::get("logger")->error( "[vscpl2drv-websrv] Exception when starting web server");
        return false;
    }

    // start the workerthread
    if (pthread_create(&m_pthreadSend, NULL, workerThreadSend, this)) {
        spdlog::get("logger")->error(
               "[vscpl2drv-websrv] Unable to start send worker thread.");
        return false;
    }

    if (pthread_create(&m_pthreadReceive, NULL, workerThreadReceive, this)) {
        spdlog::get("logger")->error(
               "[vscpl2drv-websrv] Unable to start receive worker thread.");
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
    if (m_bQuit) return;

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
    try {
        std::ifstream in(path, std::ifstream::in);
        std::stringstream strStream;
        strStream << in.rdbuf();
        //m_vscpkey = strStream.str();
    }
    catch (...) {  
        spdlog::get("logger")->error(
                "[vscpl2drv-tcpipsrv] Failed to read encryption key file [%s]",
                m_path.c_str());             
        return false;
    }

    return true;
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
    catch (json::parse_error) {
        spdlog::critical("[vscpl2drv-websrv] Failed to load/parse JSON configuration.");     
        return false;
    }

    // write
    if (m_j_config.contains("write")) {
        try {
            m_bWriteEnable = m_j_config["write"].get<bool>();
        }
        catch (const std::exception& ex) {
            spdlog::error("Failed to read 'write' Error='{}'", ex.what());    
        }
        catch(...) {
            spdlog::error("Failed to read 'write' due to unknown error.");
        }
    }
    else  {
        spdlog::error("ReadConfig: Failed to read LOGGING 'write' Defaults will be used.");
    }

    // VSCP key file
    if (m_j_config.contains("key-file")&& m_j_config["logging"].is_string()) {
        if (!readEncryptionKey(m_j_config["key-file"].get<std::string>())) {       
            spdlog::warn("[vscpl2drv-tcpipsrv] WARNING!!! Default key will be used.");
        }
    }
    else {
        spdlog::warn("[vscpl2drv-tcpipsrv] WARNING!!! Default key will be used.");
    }

    // Logging
    if (m_j_config.contains("logging") && m_j_config["logging"].is_object()) {

        json j = m_j_config["logging"];

        // Logging: file-log-level
        if (j.contains("file-log-level")) {
            std::string str;
            try {
                str = j["file-log-level"].get<std::string>();
            }
            catch (const std::exception& ex) {
                spdlog::error("[vscpl2drv-tcpipsrv]Failed to read 'file-log-level' Error='{}'", ex.what());    
            }
            catch(...) {
                spdlog::error("[vscpl2drv-tcpipsrv]Failed to read 'file-log-level' due to unknown error.");
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
                spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig: LOGGING 'file-log-level' has invalid value [{}]. Default value used.",
                                str);
            }            
        } 
        else  {
            spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read LOGGING 'file-log-level' Defaults will be used.");                                        
        }

        // Logging: file-pattern
        if (j.contains("file-pattern")) {
            try {
                m_fileLogPattern = j["file-pattern"].get<std::string>();
            }
            catch (const std::exception& ex) {
                spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig:Failed to read 'file-pattern' Error='{}'", ex.what());    
            }
            catch(...) {
                spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig:Failed to read 'file-pattern' due to unknown error.");
            }
        }
        else  {
            spdlog::debug("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read LOGGING 'file-pattern' Defaults will be used.");
        }  

        // Logging: file-path
        if (j.contains("file-path")) {
            try {
                m_path_to_log_file = j["file-path"].get<std::string>();
            }
            catch (const std::exception& ex) {
                spdlog::error("Failed to read 'file-path' Error='{}'", ex.what());    
            }
            catch(...) {
                spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig:Failed to read 'file-path' due to unknown error.");
            }
        }
        else  {
            spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read LOGGING 'file-path' Defaults will be used.");
        }

        // Logging: file-max-size
        if (j.contains("file-max-size")) {
            try {
                m_max_log_size = j["file-max-size"].get<uint32_t>();
            }
            catch (const std::exception& ex) {
                spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig:Failed to read 'file-max-size' Error='{}'", ex.what());    
            }
            catch(...) {
                spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig:Failed to read 'file-max-size' due to unknown error.");
            }
        }
        else  {
            spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read LOGGING 'file-max-size' Defaults will be used.");
        }

        // Logging: file-max-files
        if (j.contains("file-max-files")) {
            try {
                m_max_log_files = j["file-max-files"].get<uint16_t>();
            }
            catch (const std::exception& ex) {
                spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig:Failed to read 'file-max-files' Error='{}'", ex.what());    
            }
            catch(...) {
                spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig:Failed to read 'file-max-files' due to unknown error.");
            }
        }
        else  {
            spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read LOGGING 'file-max-files' Defaults will be used.");
        }        

    }  // Logging
    else {
       spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig: No logging has been setup."); 
    }

    // Path to user database  
    if (m_j_config.contains("path-users")) {
        try {
            m_pathUsers = m_j_config["path-users"].get<std::string>();
            if (!m_userList.loadUsersFromFile(m_pathUsers)) {
                spdlog::critical("[vscpl2drv-tcpipsrv] ReadConfig: Failed to load users from file 'user-path'='{}'. Terminating!", m_pathUsers); 
                return false;
            }
        }
        catch (const std::exception& ex) {
            spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read 'path-users' Error='{}'", ex.what());    
        }
        catch(...) {
            spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read 'path-users' due to unknown error.");
        }
    }
    else  {
        spdlog::warn("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read 'path-users' Defaults will be used.");
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
                spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read 'in-filter' Error='{}'", ex.what());    
            }
            catch(...) {
                spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read 'in-filter' due to unknown error.");
            }
        }
        else  {
            spdlog::debug("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read LOGGING 'in-filter' Defaults will be used.");
        } 

        // IN mask
        if (j.contains("in-mask")) {
            try {
                std::string str = j["in-mask"].get<std::string>();
                vscp_readMaskFromString(&m_filterIn, str.c_str());
            }
            catch (const std::exception& ex) {
                spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read 'in-mask' Error='{}'", ex.what());    
            }
            catch(...) {
                spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read 'in-mask' due to unknown error.");
            }
        }
        else  {
            spdlog::debug("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read 'in-mask' Defaults will be used.");
        }

        // OUT filter
        if (j.contains("out-filter")) {
            try {
                std::string str = j["in-filter"].get<std::string>();
                vscp_readFilterFromString(&m_filterOut, str.c_str());
            }
            catch (const std::exception& ex) {
                spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read 'out-filter' Error='{}'", ex.what());    
            }
            catch(...) {
                spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read 'out-filter' due to unknown error.");
            }
        }
        else  {
            spdlog::debug("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read 'out-filter' Defaults will be used.");
        } 

        // OUT mask
        if (j.contains("out-mask")) {
            try {
                std::string str = j["out-mask"].get<std::string>();
                vscp_readMaskFromString(&m_filterOut, str.c_str());
            }
            catch (const std::exception& ex) {
                spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read 'out-mask' Error='{}'", ex.what());    
            }
            catch(...) {
                spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read 'out-mask' due to unknown error.");
            }
        }
        else  {
            spdlog::debug("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read 'out-mask' Defaults will be used.");
        }
    }

    //*************************************************************************
    //                             WEB-Server
    //*************************************************************************

    if (m_j_config.contains("web") && m_j_config["web"].is_object()) {
        
        json j = m_j_config["web"];

        // Enable web server
        if (j.contains("enable") && j["enable"].is_boolean()) {
            m_bEnableWebServer = j["enable"].get<bool>();
        }

        // enable-auth-domain-check
        if (j.contains("document-root") && j["document-root"].is_string()) {
            m_web_document_root = j["document-root"].get<std::string>();
        }

        // listening_ports
        if (j.contains("listening-ports") && j["listening-ports"].is_array()) {
            std::string str;
            for (json::iterator it = j["listening-ports"].begin(); it != j["listening-ports"].end(); ++it) {
                if (str.length()) str += ",";
                str += *it;
            }
            m_web_listening_ports = str;
        }
        else if (j.contains("listening-ports") && j["listening-ports"].is_string()) {
            m_web_listening_ports = j["listening-ports"].get<std::string>();
        }

        // auth-domain
        if (j.contains("auth-domain") && j["auth-domain"].is_string()) {
            m_web_authentication_domain = j["auth-domain"].get<std::string>();
        }

        // index-files
        if (j.contains("index-files") && j["index-files"].is_string()) {
            std::string str;
            for (json::iterator it = j["index-files"].begin(); it != j["index-files"].end(); ++it) {
                if (str.length()) str += ",";
                str += *it;
            }
            m_web_index_files = str;
        }
        else if (j.contains("index-files") && j["index-files"].is_string()) {
            m_web_index_files = j["index-files"].get<std::string>();
        }

        // enable-auth-domain-check
        if (j.contains("enable-auth-domain-check") && j["enable-auth-domain-check"].is_boolean()) {
            m_enable_auth_domain_check = j["enable-auth-domain-check"].get<bool>();
        }

        // access-log-file
        if (j.contains("access-log-file") && j["access-log-file"].is_string()) {
            m_access_log_file = j["access-log-file"].get<std::string>();
        }

        // error-log-file
        if (j.contains("error-log-file") && j["error-log-file"].is_string()) {
            m_error_log_file = j["error-log-file"].get<std::string>();
        }

        // protect-uri : "",
        if (j.contains("protect-uri") && j["protect-uri"].is_string()) {
            m_web_protect_uri = j["protect-uri"].get<std::string>();
        }

        // throttle : "",
        if (j.contains("throttle") && j["throttle"].is_string()) {
            m_web_throttle = j["throttle"].get<std::string>();
        }

        // enable-directory-listing : true,
        if (j.contains("enable-directory-listing") && j["enable-directory-listing"].is_boolean()) {
            m_web_enable_directory_listing = j["enable-directory-listing"].get<bool>();
        }

        // enable-keep-alive : "false",
        if (j.contains("enable-keep-alive") && j["enable-keep-alive"].is_boolean()) {
            m_web_enable_keep_alive = j["enable-keep-alive"].get<bool>();
        }

        // keep-alive-timeout_ms : 0,
        if (j.contains("keep-alive-timeout_ms") && j["keep-alive-timeout_ms"].is_number()) {
            m_web_keep_alive_timeout_ms = j["keep-alive-timeout_ms"].get<long>();
        }

        // access-control-list : "",
        if (j.contains("access-control-list") && j["access-control-list"].is_string()) {
            m_web_access_control_list = j["access-control-list"].get<std::string>();
        }

        // extra-mime-types : "",
        if (j.contains("extra-mime-types") && j["extra-mime-types"].is_string()) {
            m_web_extra_mime_types = j["extra-mime-types"].get<std::string>();
        }

        // num-threads : 50,
        if (j.contains("num-threads") && j["num-threads"].is_number()) {
            m_web_num_threads = j["num-threads"].get<int>();
        }

        // url-rewrite-patterns : "",
        if (j.contains("url-rewrite-patterns") && j["url-rewrite-patterns"].is_string()) {
            m_web_url_rewrite_patterns = j["url-rewrite-patterns"].get<std::string>();
        }

        // hide-file-patterns : "",
        if (j.contains("hide-file-patterns") && j["hide-file-patterns"].is_string()) {
            m_web_hide_file_patterns = j["hide-file-patterns"].get<std::string>();
        }

        // request-timeout-ms : 10000,
        if (j.contains("request-timeout-ms") && j["request-timeout-ms"].is_number()) {
            m_web_keep_alive_timeout_ms = j["request-timeout-ms"].get<long>();
        }

        // linger-timeout-ms : "",
        if (j.contains("linger-timeout-ms") && j["linger-timeout-ms"].is_number()) {
            m_web_linger_timeout_ms = j["linger-timeout-ms"].get<long>();
        }

        // decode-url : true,
        if (j.contains("decode-url") && j["decode-url"].is_boolean()) {
            m_web_decode_url = j["decode-url"].get<bool>();
        }

        // global-auth-file : "",
        if (j.contains("global-auth-file") && j["global-auth-file"].is_string()) {
            m_web_global_auth_file = j["global-auth-file"].get<std::string>();
        }

        // per-directory-auth-file : "",
        if (j.contains("per-directory-auth-file") && j["per-directory-auth-file"].is_string()) {
            m_web_per_directory_auth_file = j["per-directory-auth-file"].get<std::string>();
        }

        // ssi-patterns : "",
        if (j.contains("ssi-patterns") && j["ssi-patterns"].is_string()) {
            m_web_ssi_patterns = j["ssi-patterns"].get<std::string>();
        }

        // access-control-allow-origin : "*",
        if (j.contains("access-control-allow-origin") && j["access-control-allow-origin"].is_string()) {
            m_web_access_control_allow_origin = j["access-control-allow-origin"].get<std::string>();
        }

        // access-control-allow-methods : "*",
        if (j.contains("access-control-allow-methods") && j["access-control-allow-methods"].is_string()) {
            m_web_access_control_allow_methods = j["access-control-allow-methods"].get<std::string>();
        }

        // access-control-allow-headers : "*",
        if (j.contains("access-control-allow-headers") && j["access-control-allow-headers"].is_string()) {
            m_web_access_control_allow_headers = j["access-control-allow-headers"].get<std::string>();
        }

        // error-pages : "",
        if (j.contains("error-pages") && j["error-pages"].is_string()) {
            m_web_error_pages = j["error-pages"].get<std::string>();
        }

        // tcp-nodelay : 0,
        if (j.contains("tcp-nodelay") && j["tcp-nodelay"].is_number()) {
            m_web_tcp_nodelay = j["tcp-nodelay"].get<long>();
        }

        // static-file-cache-control : "",
        if (j.contains("static-file-cache-control") && j["static-file-cache-control"].is_string()) {
            m_web_static_file_cache_control = j["static-file-cache-control"].get<std::string>();
        }

        // static-file-max-age : 3600,
        if (j.contains("static-file-max-age") && j["static-file-max-age"].is_number()) {
            m_web_static_file_max_age = j["static-file-max-age"].get<long>();
        }

        // strict-transport-security-max_age : "",
        if (j.contains("strict-transport-security-max_age") && j["strict-transport-security-max_age"].is_number()) {
            m_web_strict_transport_security_max_age = j["strict-transport-security-max_age"].get<long>();
        }

        // allow-sendfile-call : true,
        if (j.contains("allow-sendfile-call") && j["allow-sendfile-call"].is_boolean()) {
            m_web_allow_sendfile_call = j["allow-sendfile-call"].get<bool>();
        }

        // additional-header : "",
        if (j.contains("additional-header") && j["additional-header"].is_string()) {
            m_web_additional_header = j["additional-header"].get<std::string>();
        }

        // max-request-size : 16384,
        if (j.contains("max-request-size") && j["max-request-size"].is_number()) {
            m_web_max_request_size = j["max-request-size"].get<long>();
        }

        // allow-index-script-resource : false,
        if (j.contains("allow-index-script-resource") && j["allow-index-script-resource"].is_boolean()) {
            m_web_allow_index_script_resource = j["allow-index-script-resource"].get<bool>();
        }

        // TLS / SSL
        if (j.contains("tls") && j["tls"].is_object()) {

            json jj = j["tls"];

            // Certificate
            if (jj.contains("certificate")) {
                try {
                    m_web_ssl_certificate = jj["certificate"].get<std::string>();
                }
                catch (const std::exception& ex) {
                    spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read 'certificate' Error='{}'", ex.what());    
                }
                catch(...) {
                    spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read 'certificate' due to unknown error.");
                }
            }
            else  {
                spdlog::debug("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read 'certificate' Defaults will be used.");
            } 

            // certificate chain
            if (jj.contains("certificate_chain")) {
                try {
                    m_web_ssl_certificate_chain = jj["certificate_chain"].get<std::string>();
                }
                catch (const std::exception& ex) {
                    spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read 'certificate_chain' Error='{}'", ex.what());    
                }
                catch(...) {
                    spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read 'certificate_chain' due to unknown error.");
                }
            }
            else  {
                spdlog::debug("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read 'certificate_chain' Defaults will be used.");
            }  

            // verify peer
            if (jj.contains("verify-peer")) {
                try {
                    m_web_ssl_verify_peer = jj["verify-peer"].get<bool>();
                }
                catch (const std::exception& ex) {
                    spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read 'verify-peer' Error='{}'", ex.what());    
                }
                catch(...) {
                    spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read 'verify-peer' due to unknown error.");
                }
            }
            else  {
                spdlog::debug("ReadConfig: Failed to read 'verify-peer' Defaults will be used.");
            } 

            // CA Path
            if (jj.contains("ca-path")) {
                try {
                    m_web_ssl_ca_path = jj["ca-path"].get<std::string>();
                }
                catch (const std::exception& ex) {
                    spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read 'ca-path' Error='{}'", ex.what());    
                }
                catch(...) {
                    spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read 'ca-path' due to unknown error.");
                }
            }
            else  {
                spdlog::debug("[vscpl2drv-tcpipsrv] ReadConfig: ReadConfig: Failed to read 'ca-path' Defaults will be used.");
            } 

            // CA File
            if (jj.contains("ca-file")) {
                try {
                    m_web_ssl_ca_file = jj["ca-file"].get<std::string>();
                }
                catch (const std::exception& ex) {
                    spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read 'ca-file' Error='{}'", ex.what());    
                }
                catch(...) {
                    spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read 'ca-file' due to unknown error.");
                }
            }
            else  {
                spdlog::debug("[vscpl2drv-tcpipsrv] ReadConfig: ReadConfig: Failed to read 'ca-file' Defaults will be used.");
            } 

            // Verify depth
            if (jj.contains("verify_depth")) {
                try {
                    m_web_ssl_verify_depth = jj["verify_depth"].get<uint16_t>();
                }
                catch (const std::exception& ex) {
                    spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read 'verify_depth' Error='{}'", ex.what());    
                }
                catch(...) {
                    spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read 'verify_depth' due to unknown error.");
                }
            }
            else  {
                spdlog::debug("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read 'verify_depth' Defaults will be used.");
            } 

            // Default verify paths
            if (jj.contains("default-verify-paths")) {
                try {
                    m_web_ssl_default_verify_paths  = jj["default-verify-paths"].get<bool>();
                }
                catch (const std::exception& ex) {
                    spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig:Failed to read 'default-verify-paths' Error='{}'", ex.what());    
                }
                catch(...) {
                    spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig:Failed to read 'default-verify-paths' due to unknown error.");
                }
            }
            else  {
                spdlog::debug("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read 'default-verify-paths' Defaults will be used.");
            } 

            // Chiper list
            if (jj.contains("cipher-list")) {
                try {
                    m_web_ssl_cipher_list = jj["cipher-list"].get<std::string>();
                }
                catch (const std::exception& ex) {
                    spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig:Failed to read 'cipher-list' Error='{}'", ex.what());    
                }
                catch(...) {
                    spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig:Failed to read 'cipher-list' due to unknown error.");
                }
            }
            else  {
                spdlog::debug("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read 'cipher-list' Defaults will be used.");
            } 

            // Protocol version
            if (jj.contains("protocol-version")) {
                try {
                    m_web_ssl_protocol_version = jj["protocol-version"].get<uint16_t>();
                }
                catch (const std::exception& ex) {
                    spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig:Failed to read 'protocol-version' Error='{}'", ex.what());    
                }
                catch(...) {
                    spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig:Failed to read 'protocol-version' due to unknown error.");
                }
            }
            else  {
                spdlog::debug("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read 'protocol-version' Defaults will be used.");
            } 

            // Short trust
            if (jj.contains("short-trust")) {
                try {
                    m_web_ssl_short_trust = jj["short-trust"].get<bool>();
                }
                catch (const std::exception& ex) {
                    spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig:Failed to read 'short-trust' Error='{}'", ex.what());    
                }
                catch(...) {
                    spdlog::error("[vscpl2drv-tcpipsrv] ReadConfig:Failed to read 'short-trust' due to unknown error.");
                }
            }
            else  {
                spdlog::debug("[vscpl2drv-tcpipsrv] ReadConfig: Failed to read 'short-trust' Defaults will be used.");
            } 

        }  // TLS


        // CGI
        if (j.contains("cgi") && j["cgi"].is_object()) {

            // cgi-interpreter
            if (j.contains("cgi-interpreter") && j["cgi-interpreter"].is_string()) {
                m_web_cgi_interpreter = j["cgi-interpreter"].get<std::string>();
            }

            // cgi-patterns
            if (j.contains("cgi-patterns") && j["cgi-patterns"].is_string()) {
                m_web_cgi_patterns = j["cgi-patterns"].get<std::string>();
            }

            // cgi-environment
            if (j.contains("cgi-environment") && j["cgi-environment"].is_string()) {
                m_web_cgi_environment = j["cgi-environment"].get<std::string>();
            }

        }  // CGI

        // Duktape
        if (j.contains("duktape") && j["duktape"].is_object()) {
            // duktape-script-patterns
            if (j.contains("duktape-script-patterns") && j["duktape-script-patterns"].is_string()) {
                m_web_duktape_script_patterns = j["duktape-script-patterns"].get<std::string>();
            }
        }  // Duktape

        // lua
        if (j.contains("lua") && j["lua"].is_object()) {
            // lua-preload-file
            if (j.contains("lua-preload-file") && j["lua-preload-file"].is_string()) {
                m_web_lua_preload_file = j["lua-preload-file"].get<std::string>();
            }
            // lua-script-patterns
            if (j.contains("lua-script-patterns") && j["lua-script-patterns"].is_string()) {
                m_web_lua_script_patterns = j["lua-script-patterns"].get<std::string>();
            }
            // lua-server-page_patterns
            if (j.contains("lua-server-page_patterns") && j["lua-server-page_patterns"].is_string()) {
                m_web_lua_server_page_patterns = j["lua-server-page_patterns"].get<std::string>();
            }
            // lua-websocket-patterns
            if (j.contains("lua-websocket-patterns") && j["lua-websocket-patterns"].is_string()) {
                m_web_lua_websocket_patterns = j["lua-websocket-patterns"].get<std::string>();
            }
            // lua-background-script
            if (j.contains("lua-background-script") && j["lua-background-script"].is_string()) {
                m_web_lua_background_script = j["lua-background-script"].get<std::string>();
            }
            // lua-background-script-params
            if (j.contains("lua-background-script-params") && j["lua-background-script-params"].is_string()) {
                m_web_lua_background_script_params = j["lua-background-script-params"].get<std::string>();
            }
        }

    }  // WEB - server

    //*************************************************************************
    //                             REST API
    //*************************************************************************

    if (m_j_config.contains("restapi") && m_j_config["restapi"].is_object()) {
        
        json j = m_j_config["restapi"];

        // enable  
        if (j.contains("enable") && j["enable"].is_boolean()) {
            m_bEnableRestApi = j["enable"].get<bool>();
        }

    }  // restapi

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
        if (j.contains("websocket-timeout-ms") && j["websocket-timeout-ms"].is_number()) {
            m_websocket_timeout_ms = j["websocket-timeout-ms"].get<long>();
        }

        // enable-websocket-ping-pong : false,
        if (j.contains("enable-websocket-ping-pong") && j["enable-websocket-ping-pong"].is_boolean()) {
            bEnable_websocket_ping_pong = j["enable-websocket-ping-pong"].get<bool>();
        }

    }  // websocket

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
//           "[vscpl2drv-websrv] HLO parser: HLO in-buffer pointer is NULL.");
//         return false;
//     }

//     if (NULL == phlo) {
//         spdlog::get("logger")->error(
//                "[vscpl2drv-websrv] HLO parser: HLO obj pointer is NULL.");
//         return false;
//     }

//     if (!size) {
//         spdlog::get("logger")->error(
//                "[vscpl2drv-websrv] HLO parser: HLO buffer size is zero.");
//         return false;
//     }

//     XML_Parser xmlParser = XML_ParserCreate("UTF-8");
//     XML_SetUserData(xmlParser, this);
//     XML_SetElementHandler(xmlParser, startHLOParser, endHLOParser);

//     void* buf = XML_GetBuffer(xmlParser, XML_BUFF_SIZE);

//     // Copy in the HLO object
//     memcpy(buf, inbuf, size);

//     if (!XML_ParseBuffer(xmlParser, size, size == 0)) {
//         spdlog::get("logger")->error( "[vscpl2drv-websrv] Failed parse XML setup.");
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
//                "[vscpl2drv-websrv] Failed to open configuration file [%s]",
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
//         spdlog::get("logger")->error( "[vscpl2drv-websrv] Failed parse XML setup.");
//         XML_ParserFree(xmlParser);
//         return false;
//     }

//     XML_ParserFree(xmlParser);

//     return true;
// }

#define TEMPLATE_SAVE_CONFIG                                                   \
    "<setup "                                                                  \
    " host=\"%s\" "                                                            \
    " port=\"%d\" "                                                            \
    " user=\"%s\" "                                                            \
    " password=\"%s\" "                                                        \
    " rxfilter=\"%s\" "                                                        \
    " rxmask=\"%s\" "                                                          \
    " txfilter=\"%s\" "                                                        \
    " txmask=\"%s\" "                                                          \
    " responsetimeout=\"%lu\" "                                                \
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
//                "[vscpl2drv-websrv] Failed to open configuration file [%s] for write",
//                m_path.c_str());
//         return false;
//     }

//     if ( strlen(buf) != fwrite( buf, sizeof(char), strlen(buf), fp ) ) {
//         spdlog::get("logger")->error(
//                "[vscpl2drv-websrv] Failed to write configuration file [%s] ",
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
//                "[vscpl2drv-websrv] HLO handler: NULL event pointer.");
//         return false;
//     }

//     CHLO hlo;
//     if (!parseHLO(pEvent->sizeData, pEvent->pdata, &hlo)) {
//         spdlog::get("logger")->error( "[vscpl2drv-websrv] Failed to parse HLO.");
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
//                     sprintf(ibuf, "%lu", (long unsigned int)m_responseTimeout);
//                     sprintf(buf,
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
        spdlog::get("logger")->error(
               "[vscpl2drv-websrv] Failed to convert event from ex to ev.");
        vscp_deleteEvent(pev);
        return false;
    }
    if (NULL != pev) {
        if (vscp_doLevel2Filter(pev, &m_filterIn)) {
            pthread_mutex_lock(&m_mutexReceiveQueue);
            m_receiveList.push_back(pev);
            sem_post(&m_semReceiveQueue);
            pthread_mutex_unlock(&m_mutexReceiveQueue);
        } else {
            vscp_deleteEvent(pev);
        }
    } else {
        spdlog::get("logger")->error(
               "[vscpl2drv-websrv] Unable to allocate event storage.");
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
    //            "%s %s ",
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
    //        "%s %s ",
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
    //                    "%s %s ",
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
    //                    "%s %s ",
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
    //        "%s %s ",
    //        VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
    //        (const char*)"Disconnect from remote VSCP TCP/IP interface [SEND].");

    return NULL;
}

//////////////////////////////////////////////////////////////////////
//                Workerthread Receive - CWrkReceiveTread
//////////////////////////////////////////////////////////////////////

void*
workerThreadReceive(void* pData)
{
    bool bRemoteConnectionLost = false;
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
    //            "%s %s ",
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
    //        "%s %s ",
    //        VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
    //        (const char*)"Connect to remote VSCP TCP/IP interface [RECEIVE].");

    // // Set receive filter
    // if (VSCP_ERROR_SUCCESS !=
    //     pObj->m_srvRemoteReceive.doCmdFilter(&pObj->m_rxfilter)) {
    //     spdlog::get("logger")->error(
    //            "%s %s ",
    //            VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
    //            (const char*)"Failed to set receiving filter.");
    // }

    // // Enter the receive loop
    // pObj->m_srvRemoteReceive.doCmdEnterReceiveLoop();

    // __attribute__((unused)) vscpEventEx eventEx;
    // while (!pObj->m_bQuit) {

    //     // Make sure the remote connection is up
    //     if (!pObj->m_srvRemoteReceive.isConnected() ||
    //         ((vscp_getMsTimeStamp() - pObj->m_srvRemoteReceive.getlastResponseTime()) >
    //          (VSCP_TCPIPLINK_DEFAULT_RECONNECT_TIME * 1000))) {

    //         if (!bRemoteConnectionLost) {

    //             bRemoteConnectionLost = true;
    //             pObj->m_srvRemoteReceive.doCmdClose();
    //             spdlog::get("logger")->error( "%s %s ", VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
    //                         (const char*)"Lost connection to remote host [Receive].");
    //         }

    //         // Wait before we try to connect again
    //         sleep(VSCP_TCPIPLINK_DEFAULT_RECONNECT_TIME);

    //         if (VSCP_ERROR_SUCCESS !=
    //             pObj->m_srvRemoteReceive.doCmdOpen(pObj->m_hostRemote,
    //                                                 pObj->m_portRemote,
    //                                                 pObj->m_usernameRemote,
    //                                                 pObj->m_passwordRemote)) {
    //             spdlog::get("logger")->error(
    //                    "%s %s ",
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

    // spdlog::get("logger")->error("%s %s ",
    //   VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
    //   (const char*)"Disconnect from remote VSCP TCP/IP interface [RECEIVE].");

    return NULL;
}


