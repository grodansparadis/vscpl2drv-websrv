// websockobj.h: interface for the socketcan class.
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
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <canal.h>
#include <canal_macro.h>
#include <dllist.h>
#include <guid.h>
#include <vscp.h>
#include <websocket.h>

// Seconds before trying to reconnect to a broken connection
#define VSCP_WS1_DEFAULT_RECONNECT_TIME 30

#define VSCP_WS1_SYSLOG_DRIVER_ID "[vscpl2drv-ws1] "
#define VSCP_LEVEL2_DLL_WS1_OBJ_MUTEX                                       \
    "___VSCP__DLL_L2TCPIPLINK_OBJ_MUTEX____"
#define VSCP_WS1_LIST_MAX_MSG 2048

// Module Local HLO op's
#define HLO_OP_LOCAL_CONNECT      HLO_OP_USER_DEFINED + 0
#define HLO_OP_LOCAL_DISCONNECT   HLO_OP_USER_DEFINED + 1

// Forward declarations
class CWrkSendTread;
class CWrkReceiveTread;
class VscpRemoteTcpIf;
class CHLO;

class CWS1
{
  public:
    /// Constructor
    CWS1();

    /// Destructor
    virtual ~CWS1();

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
      Load configuration if allowed to do so
    */
    bool doLoadConfig(void);

    /*!
      Save configuration if allowed to do so
    */
    bool doSaveConfig(void);

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

  public:

    /// Debug flag
    bool m_bDebug;

    /// Write flags
    bool m_bAllowWrite;

    /// Run flag
    bool m_bQuit;

    // Our GUID
    cguid m_guid;

    // Path to configuration file
    std::string m_path;

    /// server supplied host
    std::string m_hostRemote;

    /// Server supplied port
    int m_portRemote;

    /// Server supplied username
    std::string m_usernameRemote;

    /// Server supplied password
    std::string m_passwordRemote;

    /// Send channel id
    uint32_t txChannelID;

    /// Filter for receive
    vscpEventFilter m_rxfilter;

    /// Filter for transmitt
    vscpEventFilter m_txfilter;

    // TCP/IP link response timeout
    uint32_t m_responseTimeout;

    /// Worker threads
    pthread_t m_pthreadSend;
    pthread_t m_pthreadReceive;

    /// VSCP remote server send interface
    //VscpRemoteTcpIf m_srvRemoteSend;

    /// VSCP remote server receive interface
    //VscpRemoteTcpIf m_srvRemoteReceive;

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
};

#endif // !defined(VSCPTCPIPLINK_H__6F5CD90E_ACF7_459A_9ACB_849A57595639__INCLUDED_)