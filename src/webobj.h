// webobj.h: web-interface main class.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version
// 2 of the License, or (at your option) any later version.
//
// This file is part of the VSCP (http://www.vscp.org)
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

#if !defined(VSCPTCPIPLINK_H__6F5CD90E_ACF7_459A_9ACB_849A57595639__INCLUDED_)
#define VSCPTCPIPLINK_H__6F5CD90E_ACF7_459A_9ACB_849A57595639__INCLUDED_

#define _POSIX

#include <list>
#include <string>

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <canal.h>
#include <canal_macro.h>
#include <userlist.h>
#include <clientlist.h>
#include <guid.h>
#include <vscp.h>

#include <json.hpp>     // Needs C++11  -std=c++11

#include "spdlog/spdlog.h"
#include "spdlog/sinks/rotating_file_sink.h"

// https://github.com/nlohmann/json
using json = nlohmann::json;

// Seconds before trying to reconnect to a broken connection
#define VSCP_WS1_DEFAULT_RECONNECT_TIME 30

#define VSCP_WS_LOG_DRIVER_ID           "[vscpl2drv-ws] "
#define VSCP_LEVEL2_DLL_WS_OBJ_MUTEX    "___VSCP__DLL_L2TCPIPLINK_OBJ_MUTEX____"
#define VSCP_WS_LIST_MAX_MSG            2048

// Module Local HLO op's
#define HLO_OP_LOCAL_CONNECT      HLO_OP_USER_DEFINED + 0
#define HLO_OP_LOCAL_DISCONNECT   HLO_OP_USER_DEFINED + 1

// Forward declarations
class CWrkSendTread;
class CWrkReceiveTread;
class VscpRemoteTcpIf;
class CHLO;
class websock_session;

/*!
  CWebObj Websocket object
*/
class CWebObj
{
  public:
    /// Constructor
    CWebObj();

    /// Destructor
    virtual ~CWebObj();

    /*!
      Open
      @return True on success.
     */
    bool open(std::string &path, const cguid &guid);

    /*!
      Flush and close the log file
     */
    void close(void);

    /*!
      Parse HLO object
    */
    bool parseHLO(uint16_t size, uint8_t* inbuf, CHLO* phlo);

    /*!
      Handle high level object
    */
    bool handleHLO(vscpEvent* pEvent);

    /*!
      Read in encryption key from disk
      @param path Path to file that contains the 256 bit (32 byte) key on hexadecimal 
        string form (do separator between hex numbers "001122..eeff").
      @return true is returned on success, false otherwise.  
    */
    bool readEncryptionKey(const std::string& path);

    /*!
      Load configuration if allowed to do so
    */
    bool doLoadConfig(void);

    /*!
      Save configuration if allowed to do so
    */
    bool doSaveConfig(const std::string& path);

    /*!
        Put event on receive queue and signal
        that a new event is available

        @param ex Event to send
        @return true on success, false on failure
    */
    bool eventExToReceiveQueue(vscpEventEx& ex);

    /*!
        Add event to send queue
    */
    bool addEvent2SendQueue(const vscpEvent *pEvent);

    /*!
      Send event to MQTT broker
    */
    bool sendEvent(vscpEventEx *pex);
    bool sendEvent(vscpEvent *pev);

  public:

    /// Parsed Config file
    json m_j_config;

    /// Debug flag
    bool m_bDebug;

    /// Write flags
    bool m_bWriteEnable;

    /// Run flag
    bool m_bQuit;

    // Our GUID
    cguid m_guid;

    // The default random encryption key
    uint8_t m_vscp_key[32] = {
        0x2d, 0xbb, 0x07, 0x9a, 0x38, 0x98, 0x5a, 0xf0, 0x0e, 0xbe, 0xef, 0xe2, 0x2f, 0x9f, 0xfa, 0x0e,
        0x7f, 0x72, 0xdf, 0x06, 0xeb, 0xe4, 0x45, 0x63, 0xed, 0xf4, 0xa1, 0x07, 0x3c, 0xab, 0xc7, 0xd4
    };

    /////////////////////////////////////////////////////////
    //                      Logging
    /////////////////////////////////////////////////////////
    
    bool m_bConsoleLogEnable;                     // True to enable logging
    spdlog::level::level_enum m_consoleLogLevel;  // log level
    std::string m_consoleLogPattern;              // log file pattern

    bool m_bFileLogEnable;                        // True to enable logging
    spdlog::level::level_enum m_fileLogLevel;     // log level
    std::string m_fileLogPattern;                 // log file pattern
    std::string m_path_to_log_file;               // Path to logfile      
    uint32_t m_max_log_size;                      // Max size for logfile before rotating occures 
    uint16_t m_max_log_files;                     // Max log files to keep

    // ------------------------------------------------------------------------

    // Path to configuration file
    std::string m_path;

    /// Filter for receive
    vscpEventFilter m_filterIn;

    /// Filter for transmitt
    vscpEventFilter m_filterOut;

    // TCP/IP link response timeout
    uint32_t m_responseTimeout;

    /// Worker threads
    pthread_t m_pthreadSend;
    pthread_t m_pthreadReceive;

    //*****************************************************
    //               webserver interface
    //*****************************************************

    // Context for web server
    struct mg_context* m_web_ctx;

    // Enable webserver
    bool m_bEnableWebServer;

    // See
    // https://www.vscp.org/docs/vscpd/doku.php?id=configuring_the_vscp_daemon#webserver
    std::string m_web_document_root;
    std::string m_web_listening_ports;
    std::string m_web_index_files;
    std::string m_web_authentication_domain;

    std::string m_access_log_file;
    std::string m_error_log_file;

    bool m_enable_auth_domain_check;
    
    std::string m_web_ssl_certificate;
    std::string m_web_ssl_certificate_chain;
    bool m_web_ssl_verify_peer;
    std::string m_web_ssl_ca_path;
    std::string m_web_ssl_ca_file;
    uint16_t m_web_ssl_verify_depth;
    bool m_web_ssl_default_verify_paths;
    std::string m_web_ssl_cipher_list;
    uint8_t m_web_ssl_protocol_version;
    bool m_web_ssl_short_trust;
    long m_web_ssl_cache_timeout;
    
    std::string m_web_cgi_interpreter;
    std::string m_web_cgi_patterns;
    std::string m_web_cgi_environment;
    
    std::string m_web_protect_uri;
    std::string m_web_throttle;
    bool m_web_enable_directory_listing;
    bool m_web_enable_keep_alive;
    long m_web_keep_alive_timeout_ms;
    std::string m_web_access_control_list;
    std::string m_web_extra_mime_types;
    int m_web_num_threads;
    std::string m_web_url_rewrite_patterns;
    std::string m_web_hide_file_patterns;
    long m_web_request_timeout_ms;
    long m_web_linger_timeout_ms; // Set negative to not set
    bool m_web_decode_url;
    std::string m_web_global_auth_file;
    std::string m_web_per_directory_auth_file;
    std::string m_web_ssi_patterns;
    std::string m_web_access_control_allow_origin;
    std::string m_web_access_control_allow_methods;
    std::string m_web_access_control_allow_headers;
    std::string m_web_error_pages;
    long m_web_tcp_nodelay;
    std::string m_web_static_file_cache_control;
    long m_web_static_file_max_age;
    long m_web_strict_transport_security_max_age;
    bool m_web_allow_sendfile_call;
    std::string m_web_additional_header;
    long m_web_max_request_size;
    bool m_web_allow_index_script_resource;

    std::string m_web_duktape_script_patterns;  // *

    std::string m_web_lua_preload_file;
    std::string m_web_lua_script_patterns;
    std::string m_web_lua_server_page_patterns;
    std::string m_web_lua_websocket_patterns;
    std::string m_web_lua_background_script;
    std::string m_web_lua_background_script_params;

    std::string m_web_run_as_user;
    bool m_web_case_sensitive;

    // Protects the web session object
    pthread_mutex_t m_mutex_websrvSession;

    // Linked list of all active sessions. (websrv.h)
    std::list<struct websrv_session*> m_web_sessions;

    //**************************************************************************
    //                              REST
    //**************************************************************************

    // Protects the REST session object
    pthread_mutex_t m_mutex_restSession;

    // Session structure for REST API
    std::list<struct restsrv_session*> m_rest_sessions;

    // Enable REST API
    bool m_bEnableRestApi;

    //**************************************************************************
    //                              WEBSOCKETS
    //**************************************************************************

    bool m_bEnableWebsockets; // Enable web socket functionality
    std::string m_websocket_document_root;
    long m_websocket_timeout_ms;
    bool bEnable_websocket_ping_pong;

    // * * Websockets * *

    // Protects the websocket session object
    pthread_mutex_t m_mutex_websocketSession;

    // List of active websocket sessions
    std::list<websock_session*> m_websocketSessions;

    //**************************************************************************
    //                                USERS
    //**************************************************************************

    /// Path to file that holds users
    std::string m_pathUsers;

    // The list of users
    CUserList m_userList;

    // Mutex for users
    pthread_mutex_t m_mutex_UserList;


    //**************************************************************************
    //                                CLIENTS
    //**************************************************************************

    // The list with active clients. (protecting mutex in object)
    CClientList m_clientList;

    // Mutex for client queue
    pthread_mutex_t m_mutex_clientList;

    //**************************************************************************
    //                                SESSIONS
    //**************************************************************************

    //pthread_mutex_t m_mutex_websocketSession;
    //std::list<websock_session*> m_websocketSessions;

    // -------------------------------------------------------------------------

    // Queue
    std::list<vscpEvent*> m_sendList;
    std::list<vscpEvent*> m_receiveList;

    /*!
        Event object to indicate that there is an event in the output queue
     */
    sem_t m_semSendQueue;
    sem_t m_semReceiveQueue;

    // Mutex to protect the output queue
    pthread_mutex_t m_mutexSendQueue;
    pthread_mutex_t m_mutexReceiveQueue;

    // Max queues
    uint32_t m_maxItemsInClientSendQueue;
    uint32_t m_maxItemsInClientReceiveQueue;
};

#endif // !defined(VSCPTCPIPLINK_H__6F5CD90E_ACF7_459A_9ACB_849A57595639__INCLUDED_)
