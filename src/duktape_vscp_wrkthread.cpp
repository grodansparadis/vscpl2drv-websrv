// duktape_vscp_wrkthread.cpp
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

#include <list>
#include <string>

#include <float.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <actioncodes.h>
#include <duk_module_node.h>
#include <duktape.h>
#include <duktape_vscp_func.h>
#include <userlist.h>
#include <version.h>
#include <vscp.h>
#include <vscp_debug.h>
#include <webdefs.h>
#include <vscphelper.h>
#include <vscpremotetcpif.h>

#include "duktape_vscp_wrkthread.h"

///////////////////////////////////////////////////////////////////////////////
// actionJavascriptObj
//
// This thread executes a JavaScript
//

actionJavascriptObj::actionJavascriptObj(std::string &strScript)
{
    // OutputDebugString( "actionThreadURL: Create");
    m_strScript = strScript; // Script to execute
}

actionJavascriptObj::~actionJavascriptObj() {}

///////////////////////////////////////////////////////////////////////////////
// Javascript execution thread
//
//

void *
actionJavascriptThread(void *pData)
{
    actionJavascriptObj *pActionObj = (actionJavascriptObj *)pData;
    if (NULL == pActionObj) {
        spdlog::get("logger")->error(
               "[Javascript execution] - "
               "No control object, can't execute code.");
        return NULL;
    }

    CWebObj *pObj = (CWebObj *)pActionObj->pParent;
    if (NULL == pObj) return NULL; 

    pActionObj->m_start = vscpdatetime::Now(); // Mark start time

    // Create new JavaScript context
    duk_context *ctx = duk_create_heap_default();

    // Check if OK
    if (!ctx) {
        // Failure
        return NULL;
    }

    // Helpers
    duk_push_c_function(ctx, js_vscp_print, 1);
    duk_put_global_string(ctx, "print");

    // External module support
    duk_push_object(ctx);
    duk_push_c_function(ctx, js_resolve_module, DUK_VARARGS);
    duk_put_prop_string(ctx, -2, "resolve");
    duk_push_c_function(ctx, js_load_module, DUK_VARARGS);
    duk_put_prop_string(ctx, -2, "load");
    //duk_module_node_init(ctx);  // TODO: external module support

    // Add VSCP methods
    duk_push_c_function(ctx, js_vscp_log, DUK_VARARGS);
    duk_put_global_string(ctx, "vscp_log");

    duk_push_c_function(ctx, js_vscp_sleep, 1);
    duk_put_global_string(ctx, "vscp_sleep");

    duk_push_c_function(ctx, js_vscp_sendEvent, 1);
    duk_put_global_string(ctx, "vscp_sendEvent");

    duk_push_c_function(ctx, js_vscp_getEvent, 1);
    duk_put_global_string(ctx, "vscp_receiveEvent");

    duk_push_c_function(ctx, js_vscp_getCountEvent, 1);
    duk_put_global_string(ctx, "vscp_countEvent");

    duk_push_c_function(ctx, js_vscp_setFilter, 1);
    duk_put_global_string(ctx, "vscp_setFilter");

    duk_push_c_function(ctx, js_is_Measurement, 1);
    duk_put_global_string(ctx, "vscp_isMeasurement");

    duk_push_c_function(ctx, js_send_Measurement, 1);
    duk_put_global_string(ctx, "vscp_sendMeasurement");

    duk_push_c_function(ctx, js_get_MeasurementValue, 1);
    duk_put_global_string(ctx, "vscp_getMeasurementValue");

    duk_push_c_function(ctx, js_get_MeasurementUnit, 1);
    duk_put_global_string(ctx, "vscp_getMeasurementUnit");

    duk_push_c_function(ctx, js_get_MeasurementSensorIndex, 1);
    duk_put_global_string(ctx, "vscp_getMeasurementSensorIndex");

    duk_push_c_function(ctx, js_get_MeasurementZone, 1);
    duk_put_global_string(ctx, "vscp_getMeasurementZone");

    duk_push_c_function(ctx, js_get_MeasurementSubZone, 1);
    duk_put_global_string(ctx, "vscp_getMeasurementSubZone");

    // Save client object as a global pointer
    duk_push_pointer(ctx, (void *)pObj);
    duk_put_global_string(ctx, "vscp_webobj");

    // Create VSCP client
    pActionObj->m_pClientItem = new CClientItem();
    vscp_clearVSCPFilter(&pActionObj->m_pClientItem->m_filter);

    // Save the client object as a global pointer
    duk_push_pointer(ctx, (void *)pActionObj->m_pClientItem);
    duk_put_global_string(ctx, "vscp_clientitem");

    // reading [global object].vscp_clientItem
    duk_push_global_object(ctx); // -> stack: [ global ]
    duk_push_string(
      ctx, "vscp_clientitem"); // -> stack: [ global "vscp_clientItem" ]
    duk_get_prop(ctx, -2);     // -> stack: [ global vscp_clientItem ]
    CClientItem *pItem = (CClientItem *)duk_get_pointer(ctx, -1);
    std::string user   = pItem->m_UserName;

    //duk_bool_t rc;

    // This is an active client
    pActionObj->m_pClientItem->m_bOpen = false;
    pActionObj->m_pClientItem->m_type  = CLIENT_ITEM_INTERFACE_TYPE_CLIENT_JAVASCRIPT;
    pActionObj->m_pClientItem->setDeviceName(
      std::string("Internal daemon JavaScript client."));

    // Add the client to the Client List
    pthread_mutex_lock(&pObj->m_mutex_clientList);
    if (!pObj->m_clientList.addClient(pActionObj->m_pClientItem)) {
        // Failed to add client
        delete pActionObj->m_pClientItem;
        pActionObj->m_pClientItem = NULL;
        pthread_mutex_unlock(&pObj->m_mutex_clientList);
        spdlog::get("logger")->error(
               "[Javascript execution] - Failed to add client. "
               "Terminating thread.");
        return NULL;
    }
    pthread_mutex_unlock(&pObj->m_mutex_clientList);

    // Open the channel
    pActionObj->m_pClientItem->m_bOpen = true;

    // Execute the JavaScript
    duk_push_string(ctx, (const char *)pActionObj->m_strScript.c_str());
    if (0 != duk_peval(ctx)) {
        spdlog::get("logger")->error(
               "[Javascript execution] - JavaScript failed to execute: %s",
               duk_safe_to_string(ctx, -1));
    }

    // If the script wants to log results it can do so
    // by itself with the log function

    duk_pop(ctx); // pop eval. result

    // Close the channel
    pActionObj->m_pClientItem->m_bOpen = false;

    // Remove client and session item
    pthread_mutex_lock(&pObj->m_mutex_clientList);
    pObj->m_clientList.removeClient(pActionObj->m_pClientItem);
    pActionObj->m_pClientItem = NULL;
    pthread_mutex_unlock(&pObj->m_mutex_clientList);

    // Destroy the JavaScript context
    duk_destroy_heap(ctx);

    pActionObj->m_stop = vscpdatetime::Now(); // Mark stop time

    return NULL;
}
