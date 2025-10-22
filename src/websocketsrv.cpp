// websocketsrv.cpp
//
// This file is part of the VSCP (https://www.vscp.org)
//
// The MIT License (MIT)
//
// Copyright © 2000-2021 Ake Hedman, the VSCP project
// <akhe@vscp.org>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

#ifdef __GNUG__
//#pragma implementation
#endif

#define _POSIX

#include <fstream>
#include <iostream>
#include <map>
#include <sstream>

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "web_css.h"
#include "web_js.h"
#include "web_template.h"

#include <civetweb.h>
#include <expat.h>
#include <nlohmann/json.hpp> // Needs C++11  -std=c++11

#include <actioncodes.h>
//#include <controlobject.h>
//#include <devicelist.h>
#include <mdf.h>
#include <remotevariablecodes.h>
#include <version.h>
#include <vscp.h>
#include <vscp-aes.h>
#include <vscp-debug.h>
#include <vscphelper.h>
#include <websocketsrv.h>
#include <websrv.h>

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <nlohmann/json.hpp> // Needs C++11  -std=c++11
#include <mustache.hpp>

#include <spdlog/async.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

// https://github.com/nlohmann/json
using json = nlohmann::json;
using namespace kainjow::mustache;

///////////////////////////////////////////////////
//                 GLOBALS
///////////////////////////////////////////////////

// // Webserver
// extern struct mg_mgr gmgr;

// // Linked list of all active sessions. (webserv.h)
// extern struct websrv_Session* gp_websrv_sessions;

// // Session structure for REST API
// extern struct websrv_rest_session* gp_websrv_rest_sessions;

// Prototypes
int
webserv_url_decode(const char *src, int src_len, char *dst, int dst_len, int is_form_url_encoded);

void
webserv_util_sendheader(struct mg_connection *nc, const int returncode, const char *content);

////////////////////////////////////////////////////
//            Forward declarations
////////////////////////////////////////////////////

void
ws1_command(struct mg_connection *conn, CWebsockSession *pSession, std::string &strCmd, void *cbdata);

bool
ws1_message(struct mg_connection *conn, CWebsockSession *pSession, std::string &strWsPkt, void *cbdata);

bool
ws2_command(struct mg_connection *conn, CWebsockSession *pSession, std::string &strCmd, json &obj, void *cbdata);

bool
ws2_message(struct mg_connection *conn, CWebsockSession *pSession, std::string &strWsPkt, void *cbdata);

///////////////////////////////////////////////////
//                 WEBSOCKETS
///////////////////////////////////////////////////

// Linked list of websocket sessions
// Protected by the websocketSexxionMutex
// static CWebsockSession *gp_CWebsockSessions;

CWebsockSession::CWebsockSession(void)
{
  m_pParent    = NULL;
  m_wstypes    = WS_TYPE_1; // ws1
  m_conn       = NULL;
  m_conn_state = WEBSOCK_CONN_STATE_NULL;
  memset(m_websocket_key, 0, 33);
  memset(m_sid, 0, 33);
  m_version      = 0;
  lastActiveTime = 0;
  m_pClientItem  = NULL;
};

CWebsockSession::~CWebsockSession(void)
{
  m_pClientItem = NULL;
};

// w2msg - Message holder for W2

w2msg::w2msg(void)
{
  m_type = MSG_TYPE_COMMAND;
  memset(&m_ex, 0., sizeof(vscpEventEx));
};

w2msg::~w2msg(void) {}

///////////////////////////////////////////////////////////////////////////////
// websock_authentication
//
// client sends
//      "AUTH;iv;AES128("username:password)
//

bool
websock_authentication(struct mg_connection *conn,
                       CWebsockSession *pSession,
                       std::string &strIV,
                       std::string &strCrypto)
{
  uint8_t buf[2048], secret[2048];
  uint8_t iv[16];
  std::string strUser, strPassword;

  struct mg_context *ctx;
  const struct mg_request_info *reqinfo;
  bool bValidHost = false;

  // Check pointers
  if ((nullptr == conn) || (nullptr == pSession) || !(ctx = mg_get_context(conn)) ||
      !(reqinfo = mg_get_request_info(conn))) {
    spdlog::get("logger")->error("[ws] Authentication: Invalid "
                                 "pointers. ");
    return false;
  }

  // Get IV
  if (0 == vscp_hexStr2ByteArray(iv, 16, (const char *) strIV.c_str())) {
    spdlog::get("logger")->error("[ws] Authentication: No room for iv block. ");
    return false; // Not enough room in buffer
  }

  // Get AES128(username:password)
  size_t len;
  if (0 == (len = vscp_hexStr2ByteArray(secret, strCrypto.length(), (const char *) strCrypto.c_str()))) {
    spdlog::get("logger")->error("[ws] Authentication: No room for crypto block. ");
    return false; // Not enough room in buffer
  }

  memset(buf, 0, sizeof(buf));
  AES_CBC_decrypt_buffer(AES128, buf, secret, len, pSession->m_pParent->m_vscp_key, iv);

  spdlog::get("logger")->debug("[ws] Buf: {} ", buf);
  std::string str = std::string((const char *) buf);
  spdlog::get("logger")->debug("[ws] Decrypted: {} ", str);
  std::deque<std::string> tokens;
  vscp_split(tokens, str, ":");

  // Get username
  if (tokens.empty()) {
    spdlog::get("logger")->error("[ws] Authentication: Missing username from client. ");
    return false; // No username
  }

  strUser = tokens.front();
  tokens.pop_front();
  vscp_trim(strUser);

  // Get password
  if (tokens.empty()) {
    spdlog::get("logger")->error("[ws] Authentication: Missing password from client. ");
    return false; // No username
  }

  strPassword = tokens.front();
  tokens.pop_front();
  vscp_trim(strPassword);

  // Check if user is valid
  CUserItem *pUserItem = pSession->m_pParent->m_userList.getUser(strUser);
  if (nullptr == pUserItem) {
    spdlog::get("logger")->error("[ws] Authentication: CUserItem allocation problem ");
    return false;
  }

  // Check if remote ip is valid
  bValidHost = pUserItem->isAllowedToConnect(inet_addr(reqinfo->remote_addr));

  if (!bValidHost) {
    // Log valid login
    spdlog::get("logger")->debug("[ws] Authentication: Host "
                                 "[{}] NOT allowed to connect.",
                                 reqinfo->remote_addr);
    return false;
  }

  std::string combined_credentials = strUser + ":" + strPassword;
  if (!vscp_isPasswordValid(pUserItem->getPassword(), combined_credentials)) {
    spdlog::get("logger")->error("[ws] Authentication: User {} at host "
                                 "[{}] gave wrong password.",
                                 (const char *) strUser.c_str(),
                                 reqinfo->remote_addr);
    return false;
  }

  pSession->m_pClientItem->bAuthenticated = true;

  // Add user to client
  pSession->m_pClientItem->m_pUserItem = pUserItem;

  // Copy in the user filter
  memcpy(&pSession->m_pClientItem->m_filter, pUserItem->getUserFilter(), sizeof(vscpEventFilter));

  // Log valid login
  spdlog::get("logger")->info("[ws] Authentication: Host [{}] "
                              "User [{}] allowed to connect.",
                              reqinfo->remote_addr,
                              strUser);

  return true;
}

///////////////////////////////////////////////////////////////////////////////
// websock_new_session
//

CWebsockSession *
websock_new_session(const struct mg_connection *conn, void *cbdata)
{
  const char *pHeader;
  char ws_version[10];
  char ws_key[33];
  CWebsockSession *pSession = NULL;

  // Check pointer
  if (nullptr == conn) {
    return NULL;
  }

  CWebObj *pObj = (CWebObj *) cbdata;
  if (nullptr == pObj) {
    return NULL;
  }

  // user
  memset(ws_version, 0, sizeof(ws_version));
  if (NULL != (pHeader = mg_get_header(conn, "Sec-WebSocket-Version"))) {
    strncpy(ws_version, pHeader, std::min(strlen(pHeader) + 1, sizeof(ws_version)));
  }
  memset(ws_key, 0, sizeof(ws_key));
  if (NULL != (pHeader = mg_get_header(conn, "Sec-WebSocket-Key"))) {
    strncpy(ws_key, pHeader, std::min(strlen(pHeader) + 1, sizeof(ws_key)));
  }

  // create fresh session
  pSession = new CWebsockSession;
  if (nullptr == pSession) {
    spdlog::get("logger")->error("[ws] New session: Unable to create session object.");
    return NULL;
  }

  // Set pointer to papa
  pSession->m_pParent = pObj;

  // Generate the sid
  unsigned char iv[16];
  char hexiv[33];
  getRandomIV(iv, 16); // Generate 16 random bytes
  memset(hexiv, 0, sizeof(hexiv));
  vscp_byteArray2HexStr(hexiv, iv, 16);

  memset(pSession->m_sid, 0, sizeof(pSession->m_sid));
  memcpy(pSession->m_sid, hexiv, 32);
  memset(pSession->m_websocket_key, 0, sizeof(pSession->m_websocket_key));

  // Init.
  strcpy(pSession->m_websocket_key, ws_key); // Save key
  pSession->m_conn       = (struct mg_connection *) conn;
  pSession->m_conn_state = WEBSOCK_CONN_STATE_CONNECTED;
  pSession->m_version    = atoi(ws_version); // Store protocol version

  pSession->m_pClientItem = new CClientItem(); // Create client
  if (nullptr == pSession->m_pClientItem) {
    spdlog::get("logger")->error("[ws] New session: Unable to create client object.");
    delete pSession;
    return NULL;
  }

  pSession->m_pClientItem->bAuthenticated = false;          // Not authenticated in yet
  vscp_clearVSCPFilter(&pSession->m_pClientItem->m_filter); // Clear filter

  // This is an active client
  pSession->m_pClientItem->m_bOpen         = false;
  pSession->m_pClientItem->m_dtutc         = vscpdatetime::Now();
  pSession->m_pClientItem->m_type          = CLIENT_ITEM_INTERFACE_TYPE_CLIENT_WEBSOCKET;
  pSession->m_pClientItem->m_strDeviceName = ("Internal websocket client.");

  // Add the client to the Client List
  pthread_mutex_lock(&pSession->m_pParent->m_clientList.m_mutexItemList);
  if (!pSession->m_pParent->m_clientList.addClient(pSession->m_pClientItem)) {
    // Failed to add client
    delete pSession->m_pClientItem;
    pSession->m_pClientItem = NULL;
    pthread_mutex_unlock(&pSession->m_pParent->m_clientList.m_mutexItemList);
    spdlog::get("logger")->error("[ws] Failed to add client. Terminating thread.");
    return NULL;
  }
  pthread_mutex_unlock(&pSession->m_pParent->m_clientList.m_mutexItemList);

  pthread_mutex_lock(&pSession->m_pParent->m_mutex_websocketSession);
  pSession->m_pParent->m_websocketSessions.push_back(pSession);
  pthread_mutex_unlock(&pSession->m_pParent->m_mutex_websocketSession);

  // Use the session object as user data
  mg_set_user_connection_data(pSession->m_conn, (void *) pSession);

  return pSession;
}

///////////////////////////////////////////////////////////////////////////////
// websock_receiveEvent
//
// Receive ws1 or ws2 event from client. Event is placed in the receive queue
// of the session parent
//

bool
websock_receiveEvent(struct mg_connection *conn, CWebsockSession *pSession, vscpEventEx &ex)
{
  // Check pointer
  if (nullptr == conn) {
    spdlog::get("logger")->error("[ws] Internal error: websock_receiveEvent - conn == NULL");
    return false;
  }

  // Must have valid session object
  if (nullptr == pSession) {
    spdlog::get("logger")->error("[ws] Internal error: websock_receiveEvent - pSession == NULL");
    return false;
  }

  return pSession->m_pParent->eventExToReceiveQueue(ex);
}

///////////////////////////////////////////////////////////////////////////////
// websock_post_outgoingEvent
//

void
websock_post_outgoingEvent(CWebObj *pObj)
{
  // Must be valid pointer
  if (nullptr == pObj) {
    spdlog::get("logger")->error("[ws] websock_post_outgoingEvent: Object pointer == NULL");
    return;
  }

  pthread_mutex_lock(&pObj->m_mutex_websocketSession);

  std::list<CWebsockSession *>::iterator iter;
  for (iter = pObj->m_websocketSessions.begin(); iter != pObj->m_websocketSessions.end(); ++iter) {

    CWebsockSession *pSession = *iter;
    if (nullptr == pSession) {
      spdlog::get("logger")->error("[ws] websock_post_outgoingEvent: Session pointer == NULL");
      continue;
    }

    // Should be a client item... hmm.... client disconnected
    if (nullptr == pSession->m_pClientItem) {
      spdlog::get("logger")->error("[ws] websock_post_outgoingEvent: Client item == NULL");
      continue;
    }

    // Must be connected
    if (pSession->m_conn_state < WEBSOCK_CONN_STATE_CONNECTED) {
      continue;
    }

    // Must have valid connection object
    if (nullptr == pSession->m_conn) {
      continue;
    }

    // Must be something to send
    if (pSession->m_pClientItem->m_bOpen && pSession->m_pClientItem->m_clientInputQueue.size()) {

      vscpEvent *pEvent;
      pthread_mutex_lock(&pSession->m_pClientItem->m_mutexClientInputQueue);
      pEvent = pSession->m_pClientItem->m_clientInputQueue.front();
      pSession->m_pClientItem->m_clientInputQueue.pop_front();
      pthread_mutex_unlock(&pSession->m_pClientItem->m_mutexClientInputQueue);

      if (NULL != pEvent) {
        // Run event through filter
        if (vscp_doLevel2Filter(pEvent, &pSession->m_pClientItem->m_filter)) {

          // User must be authorized to receive events
          if (!(pSession->m_pClientItem->m_pUserItem->getUserRights() & VSCP_USER_RIGHT_ALLOW_RCV_EVENT)) {
            continue;
          }

          if (WS_TYPE_1 == pSession->m_wstypes) {
            std::string str;
            if (vscp_convertEventToString(str, pEvent)) {
              spdlog::get("logger")->debug("[ws] Received ws event {}", str);

              // Write it out
              str = ("E;") + str;
              mg_websocket_write(pSession->m_conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());
            }
          }
          else if (WS_TYPE_2 == pSession->m_wstypes) {
            std::string strEvent;
            vscp_convertEventToJSON(strEvent, pEvent);
            std::string str = vscp_str_format(WS2_EVENT, strEvent.c_str());
            mg_websocket_write(pSession->m_conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());
          }
        } // filter

        // Remove the event
        vscp_deleteEvent_v2(&pEvent);

      } // Valid pEvent pointer

    } // events available

  } // for

  pthread_mutex_unlock(&pObj->m_mutex_websocketSession);
}

////////////////////////////////////////////////////////////////////////////////
// ws1_connectHandler
//

int
ws1_connectHandler(const struct mg_connection *conn, void *cbdata)
{
  struct mg_context *ctx = mg_get_context(conn);
  int reject             = 1;

  // Check pointers
  if (nullptr == conn) {
    return WEB_ERROR;
  }

  if (nullptr == ctx) {
    return WEB_ERROR;
  }

  CWebObj *pObj = (CWebObj *) cbdata;
  if (nullptr == pObj) {
    return WEB_ERROR;
  }

  mg_lock_context(ctx);
  CWebsockSession *pSession = websock_new_session(conn, cbdata);

  if (NULL != pSession) {
    reject = 0;
  }

  // This is a WS1 type connection
  pSession->m_wstypes = WS_TYPE_1;

  mg_unlock_context(ctx);

  spdlog::get("logger")->error("[ws1] WS1 Connection: client {}", (reject ? "rejected" : "accepted"));

  return reject;
}

////////////////////////////////////////////////////////////////////////////////
// ws1_closeHandler
//

void
ws1_closeHandler(const struct mg_connection *conn, void *cbdata)
{
  struct mg_context *ctx    = mg_get_context(conn);
  CWebsockSession *pSession = (CWebsockSession *) mg_get_user_connection_data(conn);

  if (nullptr == conn) {
    return;
  }

  if (nullptr == pSession) {
    return;
  }

  if (pSession->m_conn != conn) {
    return;
  }

  if (pSession->m_conn_state < WEBSOCK_CONN_STATE_CONNECTED) {
    return;
  }

  CWebObj *pObj = (CWebObj *) cbdata;
  if (nullptr == pObj) {
    return;
  }

  mg_lock_context(ctx);

  // Record activity
  pSession->lastActiveTime = time(NULL);

  pSession->m_conn_state = WEBSOCK_CONN_STATE_NULL;
  pSession->m_conn       = NULL;
  pSession->m_pParent->m_clientList.removeClient(pSession->m_pClientItem);
  pSession->m_pClientItem = NULL;

  pthread_mutex_lock(&pSession->m_pParent->m_mutex_websocketSession);
  // Remove session
  pSession->m_pParent->m_websocketSessions.remove(pSession);
  delete pSession;
  pthread_mutex_unlock(&pSession->m_pParent->m_mutex_websocketSession);

  mg_unlock_context(ctx);
}

////////////////////////////////////////////////////////////////////////////////
// ws1_readyHandler
//

void
ws1_readyHandler(struct mg_connection *conn, void *cbdata)
{
  CWebsockSession *pSession = (CWebsockSession *) mg_get_user_connection_data(conn);

  // Check pointers
  if (nullptr == conn) {
    return;
  }

  if (nullptr == pSession) {
    return;
  }

  if (pSession->m_conn != conn) {
    return;
  }

  if (pSession->m_conn_state < WEBSOCK_CONN_STATE_CONNECTED) {
    return;
  }

  CWebObj *pObj = (CWebObj *) cbdata;
  if (nullptr == pObj) {
    return;
  }

  // Record activity
  pSession->lastActiveTime = time(NULL);

  // Start authentication
  std::string str = vscp_str_format(("+;AUTH0;%s"), pSession->m_sid);
  mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());

  pSession->m_conn_state = WEBSOCK_CONN_STATE_DATA;
}

////////////////////////////////////////////////////////////////////////////////
// ws1_dataHandler
//

int
ws1_dataHandler(struct mg_connection *conn, int bits, char *data, size_t len, void *cbdata)
{
  std::string strWsPkt;
  CWebsockSession *pSession = (CWebsockSession *) mg_get_user_connection_data(conn);

  // Check pointers
  if (nullptr == conn) {
    return WEB_ERROR;
  }

  if (nullptr == pSession) {
    return WEB_ERROR;
  }

  if (pSession->m_conn != conn) {
    return WEB_ERROR;
  }

  if (pSession->m_conn_state < WEBSOCK_CONN_STATE_CONNECTED) {
    return WEB_ERROR;
  }

  CWebObj *pObj = (CWebObj *) cbdata;
  if (nullptr == pObj) {
    return WEB_ERROR;
  }

  // Record activity
  pSession->lastActiveTime = time(NULL);

  switch (((unsigned char) bits) & 0x0F) {

    case MG_WEBSOCKET_OPCODE_CONTINUATION:
      spdlog::get("logger")->debug("[ws1] opcode = Continuation");

      // Save and concatenate mesage
      pSession->m_strConcatenated += std::string(data, len);

      // if last process is
      if (1 & bits) {
        try {
          if (!ws1_message(conn, pSession, pSession->m_strConcatenated, cbdata)) {
            return WEB_ERROR;
          }
        }
        catch (...) {
          spdlog::get("logger")->error("[ws1] Exception occurred ws1_message concat");
        }
      }
      break;

    // https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers
    case MG_WEBSOCKET_OPCODE_TEXT:
      spdlog::get("logger")->debug("[ws1] opcode = text[{}]", strWsPkt);
      if (1 & bits) {
        try {
          strWsPkt = std::string(data, len);
          if (!ws1_message(conn, pSession, strWsPkt, cbdata)) {
            return WEB_ERROR;
          }
        }
        catch (...) {
          spdlog::get("logger")->error("[ws1] Exception occurred ws1_message");
        }
      }
      else {
        // Store first part
        pSession->m_strConcatenated = std::string(data, len);
      }
      break;

    case MG_WEBSOCKET_OPCODE_BINARY:
      spdlog::get("logger")->debug("[ws1] opcode = BINARY");
      break;

    case MG_WEBSOCKET_OPCODE_CONNECTION_CLOSE:
      spdlog::get("logger")->debug("[ws1] opcode = Connection close");
      break;

    case MG_WEBSOCKET_OPCODE_PING:
      spdlog::get("logger")->debug("[ws1] Ping received/Pong sent,");
      mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_PONG, NULL, 0);
      break;

    case MG_WEBSOCKET_OPCODE_PONG:
      spdlog::get("logger")->debug("[ws1] Pong received/Ping sent,");
      mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_PING, NULL, 0);
      break;

    default:
      break;
  }

  return WEB_OK;
}

///////////////////////////////////////////////////////////////////////////////
// ws1_message
//

bool
ws1_message(struct mg_connection *conn, CWebsockSession *pSession, std::string &strWsPkt, void *cbdata)
{
  std::string str;

  // Check pointer
  if (nullptr == conn) {
    return false;
  }

  if (nullptr == pSession) {
    return false;
  }

  CWebObj *pObj = (CWebObj *) cbdata;
  if (nullptr == pObj) {
    return false;
  }

  vscp_trim(strWsPkt);

  switch (strWsPkt[0]) {

    // Command - | 'C' | command type (byte) | data |
    case 'C':
      // Point beyond initial info "C;"
      strWsPkt = vscp_str_right(strWsPkt, strWsPkt.length() - 2);
      try {
        ws1_command(conn, pSession, strWsPkt, cbdata);
      }
      catch (...) {
        spdlog::get("logger")->error("[ws1] Exception occurred ws1_command");
        str = vscp_str_format(("-;C;%d;%s"), (int) WEBSOCK_ERROR_GENERAL, WEBSOCK_STR_ERROR_GENERAL);
        mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());
      }
      break;

    // Event | 'E' ; head(byte) , vscp_class(unsigned short) ,
    // vscp_type(unsigned
    //              short) , GUID(16*byte), data(0-487 bytes) |
    case 'E': {

      // Must be authorized to do this
      if ((nullptr == pSession->m_pClientItem) || !pSession->m_pClientItem->bAuthenticated) {

        str = vscp_str_format(("-;%d;%s"), (int) WEBSOCK_ERROR_NOT_AUTHORIZED, WEBSOCK_STR_ERROR_NOT_AUTHORIZED);
        mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());

        spdlog::get("logger")->error("[ws1] User [{}] is not authorized.\n",
                                     pSession->m_pClientItem->m_pUserItem->getUserName().c_str());

        return true;
      }

      // User must be allowed to send events
      if (!(pSession->m_pClientItem->m_pUserItem->getUserRights() & VSCP_USER_RIGHT_ALLOW_SEND_EVENT)) {

        str = vscp_str_format(("-;%d;%s"),
                              (int) WEBSOCK_ERROR_NOT_ALLOWED_TO_DO_THAT,
                              WEBSOCK_STR_ERROR_NOT_ALLOWED_TO_DO_THAT);

        mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());

        spdlog::get("logger")->error("[ws1] User [{}] is not "
                                     "allowed to send events.",
                                     pSession->m_pClientItem->m_pUserItem->getUserName());

        return true; // We still leave channel open
      }

      // Point beyond initial info "E;"
      strWsPkt = vscp_str_right(strWsPkt, strWsPkt.length() - 2);
      vscpEventEx ex;

      try {
        if (vscp_convertStringToEventEx(&ex, strWsPkt)) {

          // If GUID is all null give it GUID of interface
          if (vscp_isGUIDEmpty(ex.GUID)) {
            pSession->m_pClientItem->m_guid.writeGUID(ex.GUID);
          }

          // Is this user allowed to send events
          if (!(pSession->m_pClientItem->m_pUserItem->getUserRights() & VSCP_USER_RIGHT_ALLOW_SEND_EVENT)) {

            str = vscp_str_format(("-;%d;%s"),
                                  (int) WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT,
                                  WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT);

            mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());

            spdlog::get("logger")->error("[ws1] User [{}] is not "
                                         "allowed to send events.",
                                         pSession->m_pClientItem->m_pUserItem->getUserName());

            return true; // We still leave channel open
          }

          // Is user allowed to send CLASS1.PROTOCOL events
          if ((VSCP_CLASS1_PROTOCOL == ex.vscp_class) && (VSCP_CLASS2_LEVEL1_PROTOCOL == ex.vscp_class) &&
              !(pSession->m_pClientItem->m_pUserItem->getUserRights() & VSCP_USER_RIGHT_ALLOW_SEND_L1CTRL_EVENT)) {

            str = vscp_str_format(("-;%d;%s"),
                                  (int) WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT,
                                  WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT);
            mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());

            spdlog::get("logger")->error("[ws1] User [{}] is not "
                                         "authorized to send CLASS1.PROTOCOL events.",
                                         pSession->m_pClientItem->m_pUserItem->getUserName());

            return true;
          }

          // Is user allowed to send CLASS2.PROTOCOL events
          if ((VSCP_CLASS2_PROTOCOL == ex.vscp_class) &&
              !(pSession->m_pClientItem->m_pUserItem->getUserRights() & VSCP_USER_RIGHT_ALLOW_SEND_L2CTRL_EVENT)) {

            str = vscp_str_format(("-;%d;%s"),
                                  (int) WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT,
                                  WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT);
            mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());

            spdlog::get("logger")->error("[ws1] User [{}] is not "
                                         "authorized to send CLASS2.PROTOCOL events.",
                                         pSession->m_pClientItem->m_pUserItem->getUserName());

            return true;
          }

          // Is user allowed to send CLASS2.HLO events
          if ((VSCP_CLASS2_HLO == ex.vscp_class) &&
              !(pSession->m_pClientItem->m_pUserItem->getUserRights() & VSCP_USER_RIGHT_ALLOW_SEND_HLO_EVENT)) {

            str = vscp_str_format(("-;%d;%s"),
                                  (int) WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT,
                                  WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT);
            mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());

            spdlog::get("logger")->error("[ws1] User [{}] is not "
                                         "authorized to send CLASS2.HLO events.",
                                         pSession->m_pClientItem->m_pUserItem->getUserName());

            return true;
          }

          // Check if this user is allowed to send this event
          if (!pSession->m_pClientItem->m_pUserItem->isUserAllowedToSendEvent(ex.vscp_class, ex.vscp_type)) {

            str = vscp_str_format(("-;%d;%s"),
                                  (int) WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT,
                                  WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT);

            mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());

            spdlog::get("logger")->error("[ws1] User [{}] is not allowed to "
                                         "send event class={} type={}.",
                                         pSession->m_pClientItem->m_pUserItem->getUserName(),
                                         ex.vscp_class,
                                         ex.vscp_type);

            return true; // Keep connection open
          }

          ex.obid = pSession->m_pClientItem->m_clientID;
          if (websock_receiveEvent(conn, pSession, ex)) {
            mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, "+;EVENT", 7);
            spdlog::get("logger")->debug("[ws1] Received ws1 event {}", strWsPkt);
          }
          else {
            str = vscp_str_format(("-;%d;%s"), (int) WEBSOCK_ERROR_TX_BUFFER_FULL, WEBSOCK_STR_ERROR_TX_BUFFER_FULL);
            mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());
          }
        }
      }
      catch (...) {
        spdlog::get("logger")->error("[ws1] Exception occurred send event");
        str = vscp_str_format(("-;E;%d;%s"), (int) WEBSOCK_ERROR_GENERAL, WEBSOCK_STR_ERROR_GENERAL);
        mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());
      }

    } break;

    // Unknown command
    default:
      break;
  }

  return true;
}

////////////////////////////////////////////////////////////////////////////////
// ws1_command
//

void
ws1_command(struct mg_connection *conn, CWebsockSession *pSession, std::string &strCmd, void *cbdata)
{
  std::string str; // Worker string
  std::string strTok;

  // Check pointer
  if (nullptr == conn) {
    return;
  }

  if (nullptr == pSession) {
    return;
  }

  CWebObj *pObj = (CWebObj *) cbdata;
  if (nullptr == pObj) {
    return;
  }

  spdlog::get("logger")->debug("[ws1] Command = {}", strCmd);

  std::deque<std::string> tokens;
  vscp_split(tokens, strCmd, ";");

  // Get command
  if (!tokens.empty()) {
    strTok = tokens.front();
    tokens.pop_front();
    vscp_trim(strTok);
    vscp_makeUpper(strTok);
  }
  else {
    std::string str = vscp_str_format(("-;%d;%s"), (int) WEBSOCK_ERROR_SYNTAX_ERROR, WEBSOCK_STR_ERROR_SYNTAX_ERROR);
    mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());
    return;
  }

  // ------------------------------------------------------------------------
  //                                NOOP
  //-------------------------------------------------------------------------

  if (vscp_startsWith(strTok, "NOOP")) {
    mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, "+;NOOP", 6);
  }

  // ------------------------------------------------------------------------
  //                               CHALLENGE
  //-------------------------------------------------------------------------

  else if (vscp_startsWith(strTok, "CHALLENGE")) {

    // Send authentication challenge
    if ((nullptr == pSession->m_pClientItem) || !pSession->m_pClientItem->bAuthenticated) {

      // Start authentication
      str = vscp_str_format(("+;AUTH0;%s"), pSession->m_sid);
      mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());
    }
  }

  // ------------------------------------------------------------------------
  //                                AUTH
  //-------------------------------------------------------------------------

  // AUTH;iv;aes128
  else if (vscp_startsWith(strTok, "AUTH")) {

    try {
      std::string str;
      std::string strUser;
      std::string strIV = tokens.front();
      tokens.pop_front();
      std::string strCrypto = tokens.front();
      tokens.pop_front();
      if (websock_authentication(conn, pSession, strIV, strCrypto)) {
        std::string userSettings;
        pSession->m_pClientItem->m_pUserItem->getAsString(userSettings);
        str = vscp_str_format(("+;AUTH1;%s"), (const char *) userSettings.c_str());
        mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());
      }
      else {

        str = vscp_str_format(("-;AUTH;%d;%s"), (int) WEBSOCK_ERROR_NOT_AUTHORIZED, WEBSOCK_STR_ERROR_NOT_AUTHORIZED);
        mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());
        pSession->m_pClientItem->bAuthenticated = false; // Authenticated
      }
    }
    catch (...) {
      spdlog::get("logger")->error("[ws1] AUTH failed (syntax)");
      str = vscp_str_format(("-;AUTH;%d;%s"), (int) WEBSOCK_ERROR_SYNTAX_ERROR, WEBSOCK_STR_ERROR_SYNTAX_ERROR);
      mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());
    }
  }

  // ------------------------------------------------------------------------
  //                                OPEN
  //-------------------------------------------------------------------------

  else if (vscp_startsWith(strTok, "OPEN")) {

    // Must be authorized to do this
    if ((nullptr == pSession->m_pClientItem) || !pSession->m_pClientItem->bAuthenticated) {

      str = vscp_str_format(("-;OPEN;%d;%s"), (int) WEBSOCK_ERROR_NOT_AUTHORIZED, WEBSOCK_STR_ERROR_NOT_AUTHORIZED);

      mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());

      return; // We still leave channel open
    }

    pSession->m_pClientItem->m_bOpen = true;
    mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, "+;OPEN", 6);
  }

  // ------------------------------------------------------------------------
  //                                CLOSE
  //-------------------------------------------------------------------------

  else if (vscp_startsWith(strTok, "CLOSE")) {
    pSession->m_pClientItem->m_bOpen = false;
    mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, "+;CLOSE", 7);
  }

  // ------------------------------------------------------------------------
  //                             SETFILTER/SF
  //-------------------------------------------------------------------------

  else if (vscp_startsWith(strTok, "SETFILTER") || vscp_startsWith(strTok, "SF")) {

    unsigned char ifGUID[16];
    memset(ifGUID, 0, 16);

    // Must be authorized to do this
    if ((nullptr == pSession->m_pClientItem) || !pSession->m_pClientItem->bAuthenticated) {

      str = vscp_str_format(("-;SF;%d;%s"), (int) WEBSOCK_ERROR_NOT_AUTHORIZED, WEBSOCK_STR_ERROR_NOT_AUTHORIZED);

      mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());

      spdlog::get("logger")->error("[ws1] User/host not authorized to set a filter.");

      return; // We still leave channel open
    }

    // Check privilege
    if (!(pSession->m_pClientItem->m_pUserItem->getUserRights() & VSCP_USER_RIGHT_ALLOW_SETFILTER)) {

      str = vscp_str_format(("-;SF;%d;%s"),
                            (int) WEBSOCK_ERROR_NOT_ALLOWED_TO_DO_THAT,
                            WEBSOCK_STR_ERROR_NOT_ALLOWED_TO_DO_THAT);

      mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());

      spdlog::get("logger")->error("[ws1] User [{}] not "
                                   "allowed to set a filter.",
                                   pSession->m_pClientItem->m_pUserItem->getUserName());
      return; // We still leave channel open
    }

    // Get filter
    if (!tokens.empty()) {

      strTok = tokens.front();
      tokens.pop_front();

      pthread_mutex_lock(&pSession->m_pClientItem->m_mutexClientInputQueue);
      if (!vscp_readFilterFromString(&pSession->m_pClientItem->m_filter, strTok)) {
        str = vscp_str_format(("-;SF;%d;%s"), (int) WEBSOCK_ERROR_SYNTAX_ERROR, WEBSOCK_STR_ERROR_SYNTAX_ERROR);
        mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());
        pthread_mutex_unlock(&pSession->m_pClientItem->m_mutexClientInputQueue);
        return;
      }
      pthread_mutex_unlock(&pSession->m_pClientItem->m_mutexClientInputQueue);
    }
    else {
      str = vscp_str_format(("-;SF;%d;%s"), (int) WEBSOCK_ERROR_SYNTAX_ERROR, WEBSOCK_STR_ERROR_SYNTAX_ERROR);
      mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());
      return;
    }

    // Get mask
    if (!tokens.empty()) {
      strTok = tokens.front();
      tokens.pop_front();

      pthread_mutex_lock(&pSession->m_pClientItem->m_mutexClientInputQueue);
      if (!vscp_readMaskFromString(&pSession->m_pClientItem->m_filter, strTok)) {
        str = vscp_str_format(("-;SF;%d;%s"), (int) WEBSOCK_ERROR_SYNTAX_ERROR, WEBSOCK_STR_ERROR_SYNTAX_ERROR);
        mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());
        pthread_mutex_unlock(&pSession->m_pClientItem->m_mutexClientInputQueue);
        return;
      }
      pthread_mutex_unlock(&pSession->m_pClientItem->m_mutexClientInputQueue);
    }
    else {
      str = vscp_str_format(("-;SF;%d;%s"), (int) WEBSOCK_ERROR_SYNTAX_ERROR, WEBSOCK_STR_ERROR_SYNTAX_ERROR);
      mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());
      return;
    }

    // Positive response
    mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, "+;SF", 4);
  }

  // ------------------------------------------------------------------------
  //                           CLRQ/CLRQUEUE
  //-------------------------------------------------------------------------

  // Clear the event queue
  else if (vscp_startsWith(strTok, "CLRQUEUE") || vscp_startsWith(strTok, "CLRQ")) {

    // Must be authorized to do this
    if ((nullptr == pSession->m_pClientItem) || !pSession->m_pClientItem->bAuthenticated) {
      str = vscp_str_format(("-;CLRQ;%d;%s"), (int) WEBSOCK_ERROR_NOT_AUTHORIZED, WEBSOCK_STR_ERROR_NOT_AUTHORIZED);
      mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());
      spdlog::get("logger")->error("[ws1] User/host not authorized to clear the queue.");
      return; // We still leave channel open
    }

    std::deque<vscpEvent *>::iterator it;
    pthread_mutex_lock(&pSession->m_pClientItem->m_mutexClientInputQueue);

    for (it = pSession->m_pClientItem->m_clientInputQueue.begin();
         it != pSession->m_pClientItem->m_clientInputQueue.end();
         ++it) {
      vscpEvent *pEvent = pSession->m_pClientItem->m_clientInputQueue.front();
      pSession->m_pClientItem->m_clientInputQueue.pop_front();
      vscp_deleteEvent_v2(&pEvent);
    }

    pSession->m_pClientItem->m_clientInputQueue.clear();
    pthread_mutex_unlock(&pSession->m_pClientItem->m_mutexClientInputQueue);

    mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, "+;CLRQ", 6);
  }

  // ------------------------------------------------------------------------
  //                              VERSION
  //-------------------------------------------------------------------------

  else if (vscp_startsWith(strTok, "VERSION")) {

    std::string strvalue;

    std::string strResult = ("+;VERSION;");
    strResult += DISPLAY_VERSION;
    strResult += (";");
    strResult += vscp_str_format(("%d.%d.%d.%d"), MAJOR_VERSION, MINOR_VERSION, RELEASE_VERSION, BUILD_VERSION);
    // Positive reply
    mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) strResult.c_str(), strResult.length());
  }

  // ------------------------------------------------------------------------
  //                              COPYRIGHT
  //-------------------------------------------------------------------------

  else if (vscp_startsWith(strTok, "COPYRIGHT")) {

    std::string strvalue;

    std::string strResult = ("+;COPYRIGHT;");
    strResult += COPYRIGHT;

    // Positive reply
    mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) strResult.c_str(), strResult.length());
  }
  // ------------------------------------------------------------------------
  //                              INTERFACES
  //-------------------------------------------------------------------------

  else if (vscp_startsWith(strTok, "INTERFACES")) {

    std::string strGUID;
    std::string strResult = ("+;INTERFACES;");

    // Protect client List
    pthread_mutex_lock(&pSession->m_pParent->m_clientList.m_mutexItemList);

    std::deque<CClientItem *>::iterator it;
    for (it = pSession->m_pParent->m_clientList.m_itemList.begin();
         it != pSession->m_pParent->m_clientList.m_itemList.end();
         ++it) {

      CClientItem *pItem = *it;

      std::string str;
      pItem->m_guid.toString(strGUID);
      strResult += vscp_str_format("%d,", pItem->m_clientID);
      strResult += vscp_str_format("%d,", pItem->m_type);
      strResult += strGUID;
      strResult += std::string(",");
      strResult += pItem->m_strDeviceName;
      strResult += std::string(" | Started at ");
      strResult += pItem->m_dtutc.getISODateTime();
      strResult += std::string(";");
    }

    pthread_mutex_unlock(&pSession->m_pParent->m_clientList.m_mutexItemList);

    // Positive reply
    mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) strResult.c_str(), strResult.length());
  }
  // ------------------------------------------------------------------------
  //                              WCYD
  //-------------------------------------------------------------------------

  else if (vscp_startsWith(strTok, "WCYD") || vscp_startsWith(strTok, "WHATCANYOUDO")) {

    std::string strResult = ("+;WCYD;");
    uint8_t capabilities[8];

    // pSession->m_pParent->getVscpCapabilities(capabilities);  // TODO:
    strResult = vscp_str_format("%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X\r\n",
                                capabilities[7],
                                capabilities[6],
                                capabilities[5],
                                capabilities[4],
                                capabilities[3],
                                capabilities[2],
                                capabilities[1],
                                capabilities[0]);

    // Positive reply
    mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) strResult.c_str(), strResult.length());
  }
}

// ----------------------------------------------------------------------------
//                                  WS2
// ----------------------------------------------------------------------------

////////////////////////////////////////////////////////////////////////////////
// ws2_connectHandler
//

int
ws2_connectHandler(const struct mg_connection *conn, void *cbdata)
{
  struct mg_context *ctx = mg_get_context(conn);
  int reject             = 1;

  // Check pointers
  if (nullptr == conn) {
    return WEB_ERROR;
  }

  if (nullptr == ctx) {
    return WEB_ERROR;
  }

  CWebObj *pObj = (CWebObj *) cbdata;
  if (nullptr == pObj) {
    return WEB_ERROR;
  }

  mg_lock_context(ctx);
  CWebsockSession *pSession = websock_new_session(conn, cbdata);

  if (NULL != pSession) {
    reject = 0;
  }

  // This is a WS2 type connection
  pSession->m_wstypes = WS_TYPE_2;
  mg_unlock_context(ctx);
  spdlog::get("logger")->error("[ws2] WS2 Connection: client {}", (reject ? "rejected" : "accepted"));

  return reject;
}

////////////////////////////////////////////////////////////////////////////////
// ws2_closeHandler
//

void
ws2_closeHandler(const struct mg_connection *conn, void *cbdata)

{
  struct mg_context *ctx    = mg_get_context(conn);
  CWebsockSession *pSession = (CWebsockSession *) mg_get_user_connection_data(conn);

  if (nullptr == conn) {
    return;
  }

  if (nullptr == pSession) {
    return;
  }

  if (pSession->m_conn != conn) {
    return;
  }

  if (pSession->m_conn_state < WEBSOCK_CONN_STATE_CONNECTED) {
    return;
  }

  CWebObj *pObj = (CWebObj *) cbdata;
  if (nullptr == pObj) {
    return;
  }

  mg_lock_context(ctx);

  // Record activity
  pSession->lastActiveTime = time(NULL);

  pSession->m_conn_state = WEBSOCK_CONN_STATE_NULL;
  pSession->m_conn       = NULL;
  pSession->m_pParent->m_clientList.removeClient(pSession->m_pClientItem);
  pSession->m_pClientItem = NULL;

  pthread_mutex_lock(&pSession->m_pParent->m_mutex_websocketSession);
  pSession->m_pParent->m_websocketSessions.remove(pSession);
  delete pSession;
  pthread_mutex_unlock(&pSession->m_pParent->m_mutex_websocketSession);

  mg_unlock_context(ctx);
}

#define WS2_AUTH0_TEMPLATE                                                                                             \
  "{"                                                                                                                  \
  "    \"type\" : \"+\", "                                                                                             \
  "    \"args\" : [\"AUTH0\",\"%s\"]"                                                                                  \
  "}"

////////////////////////////////////////////////////////////////////////////////
// ws2_readyHandler
//

void
ws2_readyHandler(struct mg_connection *conn, void *cbdata)
{
  CWebsockSession *pSession = (CWebsockSession *) mg_get_user_connection_data(conn);

  // Check pointers
  if (nullptr == conn) {
    return;
  }

  if (nullptr == pSession) {
    return;
  }

  if (pSession->m_conn != conn) {
    return;
  }

  if (pSession->m_conn_state < WEBSOCK_CONN_STATE_CONNECTED) {
    return;
  }

  CWebObj *pObj = (CWebObj *) cbdata;
  if (nullptr == pObj) {
    return;
  }

  // Record activity
  pSession->lastActiveTime = time(NULL);

  // Start authentication
  /* Auth0 response
      {
          "type" : "+"
          "args" : ["AUTH0","%s"]
      }
  */
  std::string str = vscp_str_format(WS2_AUTH0_TEMPLATE, pSession->m_sid);
  mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());

  pSession->m_conn_state = WEBSOCK_CONN_STATE_DATA;
}

////////////////////////////////////////////////////////////////////////////////
// ws2_dataHandler
//

int
ws2_dataHandler(struct mg_connection *conn, int bits, char *data, size_t len, void *cbdata)
{
  std::string strWsPkt;
  CWebsockSession *pSession = (CWebsockSession *) mg_get_user_connection_data(conn);

  // Check pointers
  if (nullptr == conn) {
    return WEB_ERROR;
  }

  if (nullptr == pSession) {
    return WEB_ERROR;
  }

  if (pSession->m_conn != conn) {
    return WEB_ERROR;
  }

  if (pSession->m_conn_state < WEBSOCK_CONN_STATE_CONNECTED) {
    return WEB_ERROR;
  }

  CWebObj *pObj = (CWebObj *) cbdata;
  if (nullptr == pObj) {
    return WEB_ERROR;
  }

  // Record activity
  pSession->lastActiveTime = time(NULL);

  switch (((unsigned char) bits) & 0x0F) {

    case MG_WEBSOCKET_OPCODE_CONTINUATION:

      spdlog::get("logger")->debug("[ws2] opcode = Continuation");

      // Save and concatenate mesage
      pSession->m_strConcatenated += std::string(data, len);

      // if last process is
      if (1 & bits) {
        try {
          if (!ws2_message(conn, pSession, pSession->m_strConcatenated, cbdata)) {
            return WEB_ERROR;
          }
        }
        catch (...) {
          spdlog::get("logger")->error("[ws2] Exception occurred ws2_message concat");
        }
      }
      break;

    // https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers
    case MG_WEBSOCKET_OPCODE_TEXT:

      spdlog::get("logger")->debug("[ws2] opcode = Text [{}]", strWsPkt);

      if (1 & bits) {
        try {
          strWsPkt = std::string(data, len);
          if (!ws2_message(conn, pSession, strWsPkt, cbdata)) {
            return WEB_ERROR;
          }
        }
        catch (...) {
          spdlog::get("logger")->error("[ws2] Exception occurred ws2_message");
        }
      }
      else {
        // Store first part
        pSession->m_strConcatenated = std::string(data, len);
      }
      break;

    case MG_WEBSOCKET_OPCODE_BINARY:
      spdlog::get("logger")->debug("[ws2] opcode = BINARY");
      break;

    case MG_WEBSOCKET_OPCODE_CONNECTION_CLOSE:
      spdlog::get("logger")->debug("[ws2] Connection close");
      break;

    case MG_WEBSOCKET_OPCODE_PING:
      spdlog::get("logger")->debug("[ws2] Ping received/Pong sent,");
      mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_PONG, data, len);
      break;

    case MG_WEBSOCKET_OPCODE_PONG:
      spdlog::get("logger")->debug("[ws2] Pong received/Ping sent,");
      mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_PING, data, len);
      break;

    default:
      break;
  }

  return WEB_OK;
}

///////////////////////////////////////////////////////////////////////////////
// ws2_message
//

bool
ws2_message(struct mg_connection *conn, CWebsockSession *pSession, std::string &strWsPkt, void *cbdata)
{
  w2msg msg;
  std::string str;
  json json_obj; // Command obj, event obj etc

  // Check pointer
  if (nullptr == conn) {
    return false;
  }

  if (nullptr == pSession) {
    return false;
  }

  CWebObj *pObj = (CWebObj *) cbdata;
  if (nullptr == pObj) {
    return false;
  }

  /*
  {
      "type": "event(E)|command(C)|response(+)|variable(V),
  }
  */
  try {
    json json_pkg = json::parse(strWsPkt.c_str());

    // "type": "event(E)|command(C)|response(+)|variable(V)
    if (json_pkg.find("type") != json_pkg.end()) {

      std::string str = json_pkg.at("type").get<std::string>();
      vscp_trim(str);
      vscp_makeUpper(str);

      // Command
      if (("COMMAND" == str) || ("CMD" == str) || ("C" == str)) {

        msg.m_type = MSG_TYPE_COMMAND;

        // Get command
        std::string strCmd = json_pkg.at("command").get<std::string>();
        vscp_trim(strCmd);
        vscp_makeUpper(strCmd);

        // Find args
        try {

          for (auto it = json_pkg.begin(); it != json_pkg.end(); ++it) {
            if ("args" == it.key()) {
              // str      = it.value();
              // json_obj = json::parse(str);
              return ws2_command(conn, pSession, strCmd, it.value(), cbdata);
            }
          }

          std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                            strCmd.c_str(),
                                            WEBSOCK_ERROR_PARSE_FORMAT,
                                            WEBSOCK_STR_ERROR_PARSE_FORMAT);
          mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, str.c_str(), str.length());

          // No arg found
          spdlog::get("logger")->error("[ws2] Failed to parse ws2 websocket command object {}", strWsPkt.c_str());
          return false;
        }
        catch (...) {
          std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                            strCmd.c_str(),
                                            WEBSOCK_ERROR_PARSE_FORMAT,
                                            WEBSOCK_STR_ERROR_PARSE_FORMAT);
          mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, str.c_str(), str.length());

          spdlog::get("logger")->error("[ws2] Failed to parse ws2 websocket command object {}", strWsPkt.c_str());

          return false;
        }
      }
      // Event
      else if (("EVENT" == str) || ("E" == str)) {
        msg.m_type = MSG_TYPE_EVENT;
        try {
          for (auto it = json_pkg.begin(); it != json_pkg.end(); ++it) {
            if ("event" == it.key()) {

              str = it.value().dump();

              // Client must be authorized to send events
              if ((nullptr == pSession->m_pClientItem) || !pSession->m_pClientItem->bAuthenticated) {

                str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                      "EVENT",
                                      (int) WEBSOCK_ERROR_NOT_AUTHORIZED,
                                      WEBSOCK_STR_ERROR_NOT_AUTHORIZED);

                mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());

                spdlog::get("logger")->error("[ws2] User [{}] is not allowed to login.",
                                             pSession->m_pClientItem->m_pUserItem->getUserName());
                return false; // 'false' - Drop connection
              }

              vscpEventEx ex;
              if (vscp_convertJSONToEventEx(&ex, str)) {

                // If GUID is all null give it GUID of interface
                if (vscp_isGUIDEmpty(ex.GUID)) {
                  pSession->m_pClientItem->m_guid.writeGUID(ex.GUID);
                }

                // Is this user allowed to send events
                if (!(pSession->m_pClientItem->m_pUserItem->getUserRights() & VSCP_USER_RIGHT_ALLOW_SEND_EVENT)) {

                  std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                                    "EVENT",
                                                    WEBSOCK_ERROR_NOT_ALLOWED_TO_DO_THAT,
                                                    WEBSOCK_STR_ERROR_NOT_ALLOWED_TO_DO_THAT);
                  mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, str.c_str(), str.length());

                  spdlog::get("logger")->error("[ws2] User [{}] is not "
                                               "allowed to send events.",
                                               pSession->m_pClientItem->m_pUserItem->getUserName());

                  return true; // 'true' leave connection open
                }

                // Is user allowed to send CLASS1.PROTOCOL
                // events
                if ((VSCP_CLASS1_PROTOCOL == ex.vscp_class) && (VSCP_CLASS2_LEVEL1_PROTOCOL == ex.vscp_class) &&
                    !(pSession->m_pClientItem->m_pUserItem->getUserRights() &
                      VSCP_USER_RIGHT_ALLOW_SEND_L1CTRL_EVENT)) {

                  std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                                    "EVENT",
                                                    WEBSOCK_ERROR_NOT_ALLOWED_TO_DO_THAT,
                                                    WEBSOCK_STR_ERROR_NOT_ALLOWED_TO_DO_THAT);
                  mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, str.c_str(), str.length());

                  spdlog::get("logger")->error("[ws2] User [{}] is not "
                                               "authorized to send CLASS1.PROTOCOL "
                                               "events.",
                                               pSession->m_pClientItem->m_pUserItem->getUserName());

                  return true; // 'true' leave connection open
                }

                // Is user allowed to send CLASS2.PROTOCOL
                // events
                if ((VSCP_CLASS2_PROTOCOL == ex.vscp_class) && !(pSession->m_pClientItem->m_pUserItem->getUserRights() &
                                                                 VSCP_USER_RIGHT_ALLOW_SEND_L2CTRL_EVENT)) {

                  std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                                    "EVENT",
                                                    WEBSOCK_ERROR_NOT_ALLOWED_TO_DO_THAT,
                                                    WEBSOCK_STR_ERROR_NOT_ALLOWED_TO_DO_THAT);
                  mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, str.c_str(), str.length());

                  spdlog::get("logger")->error("[ws2] User [{}] is not "
                                               "authorized to send CLASS2.PROTOCOL "
                                               "events.",
                                               pSession->m_pClientItem->m_pUserItem->getUserName());

                  return true; // 'true' leave connection open
                }

                // Is user allowed to send CLASS2.HLO events
                if ((VSCP_CLASS2_HLO == ex.vscp_class) &&
                    !(pSession->m_pClientItem->m_pUserItem->getUserRights() & VSCP_USER_RIGHT_ALLOW_SEND_HLO_EVENT)) {

                  std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                                    "EVENT",
                                                    WEBSOCK_ERROR_NOT_ALLOWED_TO_DO_THAT,
                                                    WEBSOCK_STR_ERROR_NOT_ALLOWED_TO_DO_THAT);
                  mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, str.c_str(), str.length());

                  spdlog::get("logger")->error("[ws2] User [{}] is not "
                                               "authorized to send CLASS2.HLO "
                                               "events.",
                                               pSession->m_pClientItem->m_pUserItem->getUserName());

                  return true; // 'true' leave connection open
                }

                // Check if this user is allowed to send this
                // event
                if (!pSession->m_pClientItem->m_pUserItem->isUserAllowedToSendEvent(ex.vscp_class, ex.vscp_type)) {

                  std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                                    "EVENT",
                                                    WEBSOCK_ERROR_NOT_ALLOWED_TO_DO_THAT,
                                                    WEBSOCK_STR_ERROR_NOT_ALLOWED_TO_DO_THAT);
                  mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, str.c_str(), str.length());

                  spdlog::get("logger")->error("ws2] User [{}] is not allowed to "
                                               "send event class={} type={}.",
                                               pSession->m_pClientItem->m_pUserItem->getUserName(),
                                               ex.vscp_class,
                                               ex.vscp_type);

                  return true; // 'true' leave connection open
                }

                ex.obid = pSession->m_pClientItem->m_clientID;
                if (websock_receiveEvent(conn, pSession, ex)) {

                  str = vscp_str_format(WS2_POSITIVE_RESPONSE, "EVENT", "null");
                  mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, str.c_str(), str.length());

                  spdlog::get("logger")->error("[ws2] Sent ws2 event {}", strWsPkt);
                }
                else {

                  str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                        "EVENT",
                                        (int) WEBSOCK_ERROR_TX_BUFFER_FULL,
                                        WEBSOCK_STR_ERROR_TX_BUFFER_FULL);
                  mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());
                  spdlog::get("logger")->error("[ws2] Transmission buffer is full {}", strWsPkt);

                  return true; // 'true' leave connection open
                }
              }
            }
          }
        }
        catch (...) {
          std::string str =
            vscp_str_format(WS2_NEGATIVE_RESPONSE, "EVENT", WEBSOCK_ERROR_PARSE_FORMAT, WEBSOCK_STR_ERROR_PARSE_FORMAT);
          mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, str.c_str(), str.length());

          spdlog::get("logger")->error("[ws2] Failed to parse ws2 websocket event object {}", strWsPkt);

          return true; // 'true' leave connection open
        }
      }
      // Positive response
      else if ("+" == str) {
        msg.m_type = MSG_TYPE_RESPONSE_POSITIVE;
        try {
          for (auto it = json_pkg.begin(); it != json_pkg.end(); ++it) {
            if ("response" == it.key()) {
              str      = it.value();
              json_obj = json::parse(str);
              break;
            }
          }
        }
        catch (...) {
          std::string str =
            vscp_str_format(WS2_NEGATIVE_RESPONSE, "EVENT", WEBSOCK_ERROR_PARSE_FORMAT, WEBSOCK_STR_ERROR_PARSE_FORMAT);
          mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, str.c_str(), str.length());

          spdlog::get("logger")->error("[ws2] Failed to parse ws2 websocket + response object {}", strWsPkt);
          return true; // 'true' leave connection open
        }
      }
      // Negative response
      else if ("-" == str) {
        msg.m_type = MSG_TYPE_RESPONSE_NEGATIVE;
        try {
          for (auto it = json_pkg.begin(); it != json_pkg.end(); ++it) {
            if ("response" == it.key()) {
              str      = it.value();
              json_obj = json::parse(str);
              break;
            }
          }
        }
        catch (...) {
          std::string str =
            vscp_str_format(WS2_NEGATIVE_RESPONSE, "EVENT", WEBSOCK_ERROR_PARSE_FORMAT, WEBSOCK_STR_ERROR_PARSE_FORMAT);
          mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, str.c_str(), str.length());

          spdlog::get("logger")->error("[ws2] Failed to parse ws2 websocket - response object {}", strWsPkt);
          return true; // 'true' leave connection open
        }
      }
      // Changed variable
      else if ("VARIABLE" == str) {
        msg.m_type = MSG_TYPE_VARIABLE;
        try {
          for (auto it = json_pkg.begin(); it != json_pkg.end(); ++it) {
            if ("variable" == it.key()) {
              str      = it.value();
              json_obj = json::parse(str);
              break;
            }
          }
        }
        catch (...) {
          std::string str =
            vscp_str_format(WS2_NEGATIVE_RESPONSE, "EVENT", WEBSOCK_ERROR_PARSE_FORMAT, WEBSOCK_STR_ERROR_PARSE_FORMAT);
          mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, str.c_str(), str.length());

          spdlog::get("logger")->error("[ws2] Failed to parse ws2 websocket variable object {}", strWsPkt);
          return true; // 'true' leave connection open
        }
      }
      else {

        std::string str =
          vscp_str_format(WS2_NEGATIVE_RESPONSE, "EVENT", WEBSOCK_ERROR_UNKNOWN_TYPE, WEBSOCK_STR_ERROR_UNKNOWN_TYPE);
        mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, str.c_str(), str.length());

        // This is a type we do not recognize
        spdlog::get("logger")->error("[ws2] Unknown ws2 websocket type {}", strWsPkt);
        return true; // 'true' leave connection open
      }
    }
  }
  catch (...) {
    std::string str =
      vscp_str_format(WS2_NEGATIVE_RESPONSE, "EVENT", WEBSOCK_ERROR_UNKNOWN_TYPE, WEBSOCK_STR_ERROR_UNKNOWN_TYPE);
    mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, str.c_str(), str.length());

    spdlog::get("logger")->error("[ws2] Failed to parse ws2 websocket command {}", strWsPkt);
    return true; // 'true' leave connection open
  }

  return true;
}

////////////////////////////////////////////////////////////////////////////////
// ws2_command
//

bool
ws2_command(struct mg_connection *conn, CWebsockSession *pSession, std::string &strCmd, json &jsonObj, void *cbdata)
{
  // Check pointer
  if (nullptr == conn) {
    return false;
  }

  if (nullptr == pSession) {
    return false;
  }

  CWebObj *pObj = (CWebObj *) cbdata;
  if (nullptr == pObj) {
    return WEB_ERROR;
  }

  spdlog::get("logger")->debug("[ws2] Command = {}", strCmd);

  // Get arguments
  std::map<std::string, std::string> argmap;
  try {
    for (auto it = jsonObj.begin(); it != jsonObj.end(); ++it) {
      if (it.value().is_string()) {
        argmap[it.key()] = it.value();
      }
    }
  }
  catch (...) {
    std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                      "SETFILTER",
                                      (int) WEBSOCK_ERROR_PARSE_FORMAT,
                                      WEBSOCK_STR_ERROR_PARSE_FORMAT);
    mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());

    spdlog::get("logger")->error("[ws2] SETFILTER parse error = {}", jsonObj.dump());

    return false;
  }

  // ------------------------------------------------------------------------
  //                                NOOP
  //-------------------------------------------------------------------------

  if ("NOOP" == strCmd) {

    std::string str = vscp_str_format(WS2_POSITIVE_RESPONSE, "NOOP", "null");
    mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, str.c_str(), str.length());
  }

  // ------------------------------------------------------------------------
  //                               CHALLENGE
  //-------------------------------------------------------------------------

  else if ("CHALLENGE" == strCmd) {

    // Send authentication challenge
    if ((nullptr == pSession->m_pClientItem) || !pSession->m_pClientItem->bAuthenticated) {

      // Start authentication
      std::string strSessionId = vscp_str_format("{\"sid\": \"%s\"}", pSession->m_sid);
      std::string str          = vscp_str_format(WS2_POSITIVE_RESPONSE, "CHALLENGE", strSessionId);
      mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());
    }
  }

  // ------------------------------------------------------------------------
  //                                AUTH
  //-------------------------------------------------------------------------

  // AUTH;iv;aes128
  else if ("AUTH" == strCmd) {

    std::string str;
    std::string strUser;
    std::string strIV     = argmap["iv"];
    std::string strCrypto = argmap["crypto"];
    if (websock_authentication(conn, pSession, strIV, strCrypto)) {
      std::string userSettings;
      pSession->m_pClientItem->m_pUserItem->getAsString(userSettings);
      str = vscp_str_format(WS2_POSITIVE_RESPONSE, "AUTH", "null");
      mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());
    }
    else {

      str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                            "AUTH",
                            (int) WEBSOCK_ERROR_NOT_AUTHORIZED,
                            WEBSOCK_STR_ERROR_NOT_AUTHORIZED);
      mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());
      pSession->m_pClientItem->bAuthenticated = false; // Authenticated
    }
  }

  // ------------------------------------------------------------------------
  //                                OPEN
  //-------------------------------------------------------------------------

  else if ("OPEN" == strCmd) {

    // Must be authorized to do this
    if ((nullptr == pSession->m_pClientItem) || !pSession->m_pClientItem->bAuthenticated) {

      std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                        "OPEN",
                                        (int) WEBSOCK_ERROR_NOT_AUTHORIZED,
                                        WEBSOCK_STR_ERROR_NOT_AUTHORIZED);
      mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());

      return false; // We still leave channel open
    }

    pSession->m_pClientItem->m_bOpen = true;
    std::string str                  = vscp_str_format(WS2_POSITIVE_RESPONSE, "OPEN", "null");
    mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());
  }

  // ------------------------------------------------------------------------
  //                                CLOSE
  //-------------------------------------------------------------------------

  else if ("CLOSE" == strCmd) {
    pSession->m_pClientItem->m_bOpen = false;
    std::string str                  = vscp_str_format(WS2_POSITIVE_RESPONSE, "CLOSE", "null");
    mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());
    sleep(1);
    mg_close_connection(conn);
  }

  // ------------------------------------------------------------------------
  //                             SETFILTER/SF
  //-------------------------------------------------------------------------

  else if (("SETFILTER" == strCmd) || ("SF" == strCmd)) {

    std::string strFilter;
    unsigned char ifGUID[16];
    memset(ifGUID, 0, 16);

    // Must be authorized to do this
    if ((nullptr == pSession->m_pClientItem) || !pSession->m_pClientItem->bAuthenticated) {

      std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                        strCmd.c_str(),
                                        (int) WEBSOCK_ERROR_NOT_AUTHORIZED,
                                        WEBSOCK_STR_ERROR_NOT_AUTHORIZED);
      mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());

      spdlog::get("logger")->error("[ws2] User/host is not authorized to set a filter.");
      return false; // We still leave channel open
    }

    // Check privilege
    if (!(pSession->m_pClientItem->m_pUserItem->getUserRights() & VSCP_USER_RIGHT_ALLOW_SETFILTER)) {

      std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                        strCmd.c_str(),
                                        (int) WEBSOCK_ERROR_NOT_ALLOWED_TO_DO_THAT,
                                        WEBSOCK_STR_ERROR_NOT_ALLOWED_TO_DO_THAT);
      mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());

      spdlog::get("logger")->error("[ws2] User [{}] is not "
                                   "allowed to set a filter.",
                                   pSession->m_pClientItem->m_pUserItem->getUserName());
      return false; // We still leave channel open
    }

    // Get filter
    if (!argmap.empty()) {

      strFilter = jsonObj.dump();

      pthread_mutex_lock(&pSession->m_pClientItem->m_mutexClientInputQueue);
      if (!vscp_readFilterMaskFromJSON(&pSession->m_pClientItem->m_filter, strFilter)) {

        std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                          strCmd.c_str(),
                                          (int) WEBSOCK_ERROR_SYNTAX_ERROR,
                                          WEBSOCK_STR_ERROR_SYNTAX_ERROR);
        mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());

        spdlog::get("logger")->error("[ws2] Set filter syntax error. [{}]", strFilter);

        pthread_mutex_unlock(&pSession->m_pClientItem->m_mutexClientInputQueue);
        return false;
      }

      pthread_mutex_unlock(&pSession->m_pClientItem->m_mutexClientInputQueue);
    }
    else {

      std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                        strCmd.c_str(),
                                        (int) WEBSOCK_ERROR_SYNTAX_ERROR,
                                        WEBSOCK_STR_ERROR_SYNTAX_ERROR);
      mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());

      spdlog::get("logger")->error("[ws2] Set filter syntax error. [{}]", strFilter);

      return false;
    }

    // Positive response
    std::string str = vscp_str_format(WS2_POSITIVE_RESPONSE, strCmd.c_str(), "null");
    mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());
  }

  // ------------------------------------------------------------------------
  //                           CLRQ/CLRQUEUE
  //-------------------------------------------------------------------------

  // Clear the event queue
  else if (("CLRQUEUE" == strCmd) || ("CLRQ" == strCmd)) {

    // Must be authorized to do this
    if ((nullptr == pSession->m_pClientItem) || !pSession->m_pClientItem->bAuthenticated) {

      std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                        strCmd.c_str(),
                                        (int) WEBSOCK_ERROR_NOT_AUTHORIZED,
                                        WEBSOCK_STR_ERROR_NOT_AUTHORIZED);
      mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());

      spdlog::get("logger")->error("[ws2] User/host is not authorized to clear the queue.");

      return false; // We still leave channel open
    }

    std::deque<vscpEvent *>::iterator it;
    pthread_mutex_lock(&pSession->m_pClientItem->m_mutexClientInputQueue);

    for (it = pSession->m_pClientItem->m_clientInputQueue.begin();
         it != pSession->m_pClientItem->m_clientInputQueue.end();
         ++it) {
      vscpEvent *pEvent = pSession->m_pClientItem->m_clientInputQueue.front();
      pSession->m_pClientItem->m_clientInputQueue.pop_front();
      vscp_deleteEvent_v2(&pEvent);
    }

    pSession->m_pClientItem->m_clientInputQueue.clear();
    pthread_mutex_unlock(&pSession->m_pClientItem->m_mutexClientInputQueue);

    std::string str = vscp_str_format(WS2_POSITIVE_RESPONSE, strCmd.c_str(), "null");
    mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());
  }

  // ------------------------------------------------------------------------
  //                              VERSION
  //-------------------------------------------------------------------------

  else if (("VERSION" == strCmd) || ("VER" == strCmd)) {

    std::string strResult;
    strResult = vscp_str_format("[%d,%d,%d,%d]", MAJOR_VERSION, MINOR_VERSION, RELEASE_VERSION, BUILD_VERSION);
    // Positive reply
    std::string str = vscp_str_format(WS2_POSITIVE_RESPONSE, strCmd.c_str(), strResult.c_str());
    mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());
  }

  // ------------------------------------------------------------------------
  //                              COPYRIGHT
  //-------------------------------------------------------------------------

  else if ("COPYRIGHT" == strCmd) {

    std::string strvalue;

    std::string strResult = ("[ \"copyright\" : \"");
    strResult += COPYRIGHT;
    strResult += "\" ]";

    // Positive reply
    std::string str = vscp_str_format(WS2_POSITIVE_RESPONSE, strCmd.c_str(), strResult.c_str());
    mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());
  }

  // ------------------------------------------------------------------------
  //                              INTERFACES
  //-------------------------------------------------------------------------

  else if ("INTERFACES" == strCmd) {

    std::string strvalue;
    std::string strGUID;
    std::deque<std::string> iflist;

    // Display Interface List
    pthread_mutex_lock(&pSession->m_pParent->m_clientList.m_mutexItemList);

    std::deque<CClientItem *>::iterator it;
    for (it = pSession->m_pParent->m_clientList.m_itemList.begin();
         it != pSession->m_pParent->m_clientList.m_itemList.end();
         ++it) {

      CClientItem *pItem = *it;

      std::string str;
      pItem->m_guid.toString(strGUID);
      str = vscp_str_format("%d,", pItem->m_clientID);
      str += vscp_str_format("%d,", pItem->m_type);
      str += strGUID;
      str += std::string(",");
      str += pItem->m_strDeviceName;
      str += std::string(" | Started at ");
      str += pItem->m_dtutc.getISODateTime();
      str += std::string("\r\n");
      iflist.push_back(str);
    }

    pthread_mutex_unlock(&pSession->m_pParent->m_clientList.m_mutexItemList);

    json j;
    j["type"]    = "+";
    j["command"] = strCmd.c_str();
    j["args"]    = iflist;

    mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, j.dump().c_str(), j.dump().length());
  }

  // ------------------------------------------------------------------------
  //                              WCYD
  //-------------------------------------------------------------------------

  else if (("WCYD" == strCmd) || ("WHATCANYOUDO" == strCmd)) {

    std::string strResult;
    uint8_t capabilities[8];

    // pSession->m_pParent->getVscpCapabilities(capabilities); TODO:
    strResult = vscp_str_format("%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X\r\n",
                                capabilities[7],
                                capabilities[6],
                                capabilities[5],
                                capabilities[4],
                                capabilities[3],
                                capabilities[2],
                                capabilities[1],
                                capabilities[0]);

    // Positive reply
    std::string str = vscp_str_format(WS2_POSITIVE_RESPONSE, strCmd.c_str(), strResult.c_str());
    mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());
  }
  else {
    std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                      strCmd,
                                      (int) WEBSOCK_ERROR_UNKNOWN_COMMAND,
                                      WEBSOCK_STR_ERROR_UNKNOWN_COMMAND);
    spdlog::get("logger")->error("[ws2] Unknown command [{}].", strCmd);

    return false;
  }

  return true;
}

////////////////////////////////////////////////////////////////////////////////
// ws2_xcommand
//

void
ws2_xcommand(struct mg_connection *conn, CWebsockSession *pSession, std::string &strCmd, void *cbdata)
{
  std::string str; // Worker string
  std::string strTok;

  // Check pointer
  if (nullptr == conn) {
    return;
  }

  if (nullptr == pSession) {
    return;
  }

  CWebObj *pObj = (CWebObj *) cbdata;
  if (nullptr == pObj) {
    return;
  }

  spdlog::get("logger")->error("[ws2] Command = {}", strCmd);

  std::deque<std::string> tokens;
  vscp_split(tokens, strCmd, ";");

  // Get command
  if (!tokens.empty()) {
    strTok = tokens.front();
    tokens.pop_front();
    vscp_trim(strTok);
    vscp_makeUpper(strTok);
  }
  else {
    std::string str = vscp_str_format(("-;%d;%s"), (int) WEBSOCK_ERROR_SYNTAX_ERROR, WEBSOCK_STR_ERROR_SYNTAX_ERROR);
    mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length());
    return;
  }

  // ------------------------------------------------------------------------
  //                                NOOP
  //-------------------------------------------------------------------------

  if (vscp_startsWith(strTok, "NOOP")) {
    mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, "+;NOOP", 6);
  }
}
