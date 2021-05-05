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
#include <syslog.h>
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
//#include <websocket.h>
#include <websrv.h>

#include "webobj.h"

#include <list>
#include <map>
#include <string>

// Buffer for XML parser
#define XML_BUFF_SIZE 50000

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
    m_bAllowWrite = false;
    m_bQuit = false;

    vscp_clearVSCPFilter(&m_rxfilter); // Accept all events
    vscp_clearVSCPFilter(&m_txfilter); // Send all events
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

    // Close syslog channel
    closelog();
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

/*
    XML configuration
    -----------------

    <setup host="localhost"
              port="9598"
              user="admin"
              password="secret"
              rxfilter=""
              rxmask=""
              txfilter=""
              txmask=""
              responsetimeout="2000" />


     <!--
        Settings for the internal webserver.

        enable          - Set to true to enable webserver functionality.
        document_root   - A directory to serve. By default, the current working directory 
                          is served. The current directory is commonly referenced as dot 
                          (.). It is recommended to use an absolute path for document_root, 
                          in order to avoid accidentally serving the wrong directory.
                          Default is: /var/lib/vscp/web/html
        listening_ports - Comma-separated list of ports to listen on. If the port is SSL, a 
                          letter s must be appended, for example, 80,443s will open port 80 
                          and port 443, and connections on port 443 will be SSL-ed. For 
                          non-SSL ports, it is allowed to append letter r, meaning 'redirect'. 
                          Redirect ports will redirect all their traffic to the first configured 
                          SSL port. For example, if listening_ports is 80r,443s, then all HTTP 
                          traffic coming at port 80 will be redirected to HTTPS port 443.

                          It is possible to specify an IP address to bind to. In this case, 
                          an IP address and a colon must be pre-pended to the port number. 
                          For example, to bind to a loopback interface on port 80 and to all 
                          interfaces on HTTPS port 443, use 127.0.0.1:80,443s.

                          If the server is built with IPv6 support, [::]:8080 can be used to 
                          listen to IPv6 connections to port 8080. IPv6 addresses of network 
                          interfaces can be specified as well, e.g. [::1]:8080 for the IPv6 
                          loopback interface.

                          [::]:80 will bind to port 80 IPv6 only. In order to use port 80 
                          for all interfaces, both IPv4 and IPv6, use either the configuration 
                          80,[::]:80 (create one socket for IPv4 and one for IPv6 only), 
                          or +80 (create one socket for both, IPv4 and IPv6). The + notation 
                          to use IPv4 and IPv6 will only work if no network interface is 
                          specified. Depending on your operating system version and IPv6 
                          network environment, some configurations might not work as expected, 
                          so you have to test to find the configuration most suitable for your 
                          needs. In case +80 does not work for your environment, you need to 
                          use 80,[::]:80.

                          It is possible to use network interface addresses (e.g., 192.0.2.3:80,
                          [2001:0db8::1234]:80). To get a list of available network interface 
                          addresses, use ipconfig (in a cmd window in Windows) or ifconfig 
                          (in a Linux shell). Alternatively, you could use the hostname for an 
                          interface. Check the hosts file of your operating system for a proper 
                          hostname (for Windows, usually found in C:\Windows\System32\drivers\etc, 
                          for most Linux distributions: /etc/hosts). E.g., to bind the IPv6 local 
                          host, you could use ip6-localhost:80. This translates to [::1]:80. 
                          Beside the hosts file, there are several other name resolution services. 
                          Using your hostname might bind you to the localhost or an external 
                          interface. You could also try hostname.local, if the proper network 
                          services are installed (Zeroconf, mDNS, Bonjour, Avahi). When using 
                          a hostname, you need to test in your particular network environment - 
                          in some cases, you might need to resort to a fixed IP address.

                          If you want to use an ephemeral port (i.e. let the operating system 
                          choose a port number), use 0 for the port number. This will make it 
                          necessary to communicate the port number to clients via other means, 
                          for example mDNS (or Zeroconf, Bonjour or Avahi).
                          Default: 8080
        index_files     - Comma-separated list of files to be treated as directory index files. 
                          If more than one matching file is present in a directory, the one 
                          listed to the left is used as a directory index.
                          Default: index.xhtml,index.html,index.htm,index.lp,index.lsp,
                                   index.lua,index.cgi,index.shtml,index.php
        enable_auth_domain_check - [yes/no] When using absolute URLs, verify the host is identical to the 
                                   authentication_domain. If enabled, requests to absolute URLs 
                                   will only be processed if they are directed to the domain. 
                                   If disabled, absolute URLs to any host will be accepted.
                                   Default: yes
        ssl_certificate - Path to SSL certificat PEM format file. If empty the
                          TLS system will not be initialised.
                          Common path: /etc/vscp/certs/server.pem 
        ssl_certificate_chain - Path to an SSL certificate chain file. As a default, 
                                the ssl_certificate file is used.
        ssl_verify_peer       - [yes/no] Enable clients certificate verification by the 
                                server. Default: no
        ssl_ca_path           - Name of a directory containing trusted CA certificates. 
                                Each file in the directory must contain only a single 
                                CA certificate. The files must be named by the subject 
                                name’s hash and an extension of “.0”. If there is more 
                                than one certificate with the same subject name they 
                                should have extensions &quot;.0&quot;, &quot;.1&quot;, &quot;.2&quot; and so on 
                                respectively.
        ssl_ca_file           - Path to a .pem file containing trusted certificates. 
                                The file may contain more than one certificate.
        ssl_verify_depth      - Sets maximum depth of certificate chain. If clients certificate 
                                chain is longer than the depth set here connection is refused.
                                Default: 9
        ssl_default_verify_paths - [yes/no] Loads default trusted certificates locations set at 
                                   openssl compile time. Default is yes
        ssl_cipher_list       - List of ciphers to present to the client. 
                                Entries should be separated by colons, commas or spaces.
                                
                                Example:
                                ALL           All available ciphers
                                ALL:!eNULL    All ciphers excluding NULL ciphers
                                AES128:!MD5   AES 128 with digests other than MD5
                                
                                See https://www.openssl.org/docs/man1.1.0/man1/ciphers.html
                                in OpenSSL documentation for full list of options and additional 
                                examples.
        ssl_protocol_version  - Sets the minimal accepted version of SSL/TLS protocol according to 
                                the table:

                                SSL2+SSL3+TLS1.0+TLS1.1+TLS1.2 	0 (default)
                                SSL3+TLS1.0+TLS1.1+TLS1.2 	1
                                TLS1.0+TLS1.1+TLS1.2 	        2
                                TLS1.1+TLS1.2 	                3
                                TLS1.2 	                        4

                                More recent versions of OpenSSL include support for TLS version 1.3. 
                                To use TLS1.3 only, set ssl_protocol_version to 5.
        ssl_short_trust       - [yes/no] Enables the use of short lived certificates. This will allow for the 
                                certificates and keys specified in ssl_certificate, ssl_ca_file and 
                                ssl_ca_path to be exchanged and reloaded while the server is running.

                                In an automated environment it is advised to first write the new pem file 
                                to a different filename and then to rename it to the configured pem file 
                                name to increase performance while swapping the certificate.

                                Disk IO performance can be improved when keeping the certificates and keys 
                                stored on a tmpfs (linux) on a system with very high throughput.  

                                Default: no  
      cgi_interpreter - Path to an executable to use as CGI interpreter for all CGI scripts 
                        regardless of the script file extension. If this option is not set 
                        (which is the default), CivetWeb looks at first line of a CGI script, 
                        [shebang line](http://en.wikipedia.org/wiki/Shebang_(Unix\)), for an 
                        interpreter (not only on Linux and Mac but also for Windows).

                        For example, if both PHP and Perl CGIs are used, then 
                        /path/to/php-cgi.exe and /path/to/perl.exe must be first lines 
                        of the respective CGI scripts. Note that paths should be either full 
                        file paths, or file paths relative to the current working directory 
                        of the CivetWeb server. If CivetWeb is started by mouse double-click 
                        on Windows, the current working directory is the directory where the 
                        vscpd executable is located.

                        If all CGIs use the same interpreter, for example they are all PHP, 
                        it is more efficient to set cgi_interpreter to the path to php-cgi.exe. 
                        The shebang line in the CGI scripts can be omitted in this case. Note 
                        that PHP scripts must use php-cgi.exe as executable, not php.exe.
                        Default: not set.
      cgi_patterns    - All files that match cgi_pattern are treated as CGI files. The default 
                        pattern allows CGI files be anywhere. To restrict CGIs to a certain 
                        directory, use /path/to/cgi-bin/**.cgi as the pattern. Note that the 
                        full file path is matched against the pattern, not the URI.
                        Default: **.cgi$|**.pl$|**.php$
      cgi_environment - Extra environment variables to be passed to the CGI script in 
                        addition to standard ones. The list must be comma-separated 
                        list of name=value pairs, like this: 
                        VARIABLE1=VALUE1,VARIABLE2=VALUE2. 

                        Default: empty   
      cgi_timeout_ms  - Maximum allowed runtime for CGI scripts. CGI processes are terminated by 
                        the server after this time. The default is no timeout, so scripts 
                        may run or block for undefined time. 
                        Default: not set.                       
      protect_uri     - Comma separated list of URI=PATH pairs, specifying that given URIs must 
                        be protected with password files specified by PATH. All Paths must be 
                        full file paths.
                        Default: empty
      put_delete_auth_file - Passwords file for PUT and DELETE requests. Without a password file, 
                             it will not be possible to PUT new files to the server or DELETE 
                             existing ones. PUT and DELETE requests might still be handled by Lua 
                             scripts and CGI paged.
                             default: none    
      trottle - Limit download speed for clients. throttle is a comma-separated list 
                of key=value pairs, where key could be:

                *                   limit speed for all connections
                x.x.x.x/mask        limit speed for specified subnet
                uri_prefix_pattern  limit speed for given URIs

                The value is a floating-point number of bytes per second, 
                optionally followed by a k or m character, meaning kilobytes 
                and megabytes respectively. A limit of 0 means unlimited rate. 
                The last matching rule wins. Examples:

                *=1k,10.0.0.0/8=0   limit all accesses to 1 kilobyte per second,
                                    but give connections the from 10.0.0.0/8 subnet
                                    unlimited speed

                /downloads/=5k      limit accesses to all URIs in `/downloads/` to
                                    5 kilobytes per second. All other accesses are 
                                    unlimited
      enable_directory_listing - [yes/no] Enable directory listing, either yes or no.
                                 Default: yes
      enable_keep_alive        - [yes/no] Enable connection keep alive, either yes or no.

                                 Allows clients to reuse TCP connection for subsequent 
                                 HTTP requests, which improves performance. For this to 
                                 work when using request handlers it is important to add 
                                 the correct Content-Length HTTP header for each request. 
                                 If this is forgotten the client will time out.

                                 Note: If you set keep_alive to yes, you should set 
                                 keep_alive_timeout_ms to some value > 0 (e.g. 500). If 
                                 you set keep_alive to no, you should set keep_alive_timeout_ms 
                                 to 0. Currently, this is done as a default value, but this 
                                 configuration is redundant. In a future version, the keep_alive 
                                 configuration option might be removed and automatically set to 
                                 yes if a timeout > 0 is set.
                                 Default: no
      keep_alive_timeout_ms    - Idle timeout between two requests in one keep-alive connection. 
                                 If keep alive is enabled, multiple requests using the same 
                                 connection are possible. This reduces the overhead for opening 
                                 and closing connections when loading several resources from one 
                                 server, but it also blocks one port and one thread at the server 
                                 during the lifetime of this connection. Unfortunately, browsers 
                                 do not close the keep-alive connection after loading all resources 
                                 required to show a website. The server closes a keep-alive connection, 
                                 if there is no additional request from the client during this timeout.

                                 Note: if enable_keep_alive is set to no the value of keep_alive_timeout_ms 
                                 should be set to 0, if enable_keep_alive is set to yes, the value of 
                                 keep_alive_timeout_ms must be >0. Currently keep_alive_timeout_ms is 
                                 ignored if enable_keep_alive is no, but future versions may drop the 
                                 enable_keep_alive configuration value and automatically use keep-alive 
                                 if keep_alive_timeout_ms is not 0.
                                 Default: 0
      access_control_list      - An Access Control List (ACL) allows restrictions to be 
                                 put on the list of IP addresses which have access to the 
                                 web server. In the case of the vscpd web server, the 
                                 ACL is a comma separated list of IP subnets, where each 
                                 subnet is pre-pended by either a - or a + sign. A plus 
                                 sign means allow, where a minus sign means deny. 
                                 If a subnet mask is omitted, such as -1.2.3.4, this 
                                 means to deny only that single IP address.

                                 Subnet masks may vary from 0 to 32, inclusive. The default 
                                 setting is to allow all accesses. On each request the full 
                                 list is traversed, and the last match wins. Examples:

                                 -0.0.0.0/0,+192.168/16    deny all accesses, only allow 
                                 192.168/16 subnet
      access_log_file          - Path to a file for access logs. Either full path, or 
                                 relative to the current working directory. If absent 
                                 (default), then accesses are not logged.
      error_log_file           - Path to a file for error logs. Either full path, or 
                                 relative to the current working directory. If absent 
                                 (default), then errors are not logged.                           
      extra_mime_types         - Extra mime types, in the form extension1=type1,exten-sion2=type2,.... 
                                 See http://en.wikipedia.org/wiki/Internet_media_type. 
                                 Extension must include a leading dot. 
                                 Example: .cpp=plain/text,.java=plain/text
                                 Default: Empty.
      num_threads              - Number of worker threads. CivetWeb handles each incoming 
                                 connection in a separate thread. Therefore, the value of 
                                 this option is effectively the number of concurrent HTTP 
                                 connections vscpd can handle.
                                 Default: 50
      url_rewrite_patterns - Comma-separated list of URL rewrites in the form of 
                             uri_pattern=file_or_directory_path. When vscpd 
                             receives any request, it constructs the file name to 
                             show by combining document_root and the URI. However, 
                             if the rewrite option is used and uri_pattern matches 
                             the requested URI, then document_root is ignored. 
                             Instead, file_or_directory_path is used, which should 
                             be a full path name or a path relative to the web 
                             servers current working directory. Note that uri_pattern, 
                             as all vscpd patterns, is a prefix pattern.

                             This makes it possible to serve many directories outside 
                             from document_root, redirect all requests to scripts, 
                             and do other tricky things. For example, to redirect all 
                             accesses to .doc files to a special script, set as:

                             **.doc$=/path/to/cgi-bin/handle_doc.cgi

                             Or, to imitate support for user home directories, do:

                             /~joe/=/home/joe/,/~bill=/home/bill/
      hilde_file_patterns          - A pattern for the files to hide. Files that match the 
                                     pattern will not show up in directory listing and return 
                                     404 Not Found if requested. Pattern must be for a file 
                                     name only, not including directory names. Example:

                                     secret.txt|**.hide

                                     Note: hide_file_patterns uses the pattern described above. 
                                     If you want to hide all files with a certain extension, 
                                     make sure to use **.extension (not just *.extension).
      request_timeout_ms           - Timeout for network read and network write operations, in 
                                     milliseconds. If a client intends to keep long-running connection, 
                                     either increase this value or (better) use keep-alive messages.
                                     Default: 30000
      linger_timeout_ms            - Set TCP socket linger timeout before closing sockets (SO_LINGER option). 
                                     The configured value is a timeout in milliseconds. Setting the value 
                                     to 0 will yield in abortive close (if the socket is closed from the 
                                     server side). Setting the value to -1 will turn off linger. If the 
                                     value is not set (or set to -2), vscpd will not set the linger 
                                     option at all.

                                     Note: For consistency with other timeout configurations, the value 
                                     is configured in milliseconds. However, the TCP socket layer usually 
                                     only offers a timeout in seconds, so the value should be an integer 
                                     multiple of 1000.
                                     default: -2
      decode_url                   - [yes/no]URL encoded request strings are decoded in the server, 
                                     unless it is disabled by setting this option to no.
                                     Default: yes
      global_auth_file             - Path to a global passwords file, either full path or relative 
                                     to the current working directory. If set, per-directory .htpasswd 
                                     files are ignored, and all requests are authorized against that file.

                                     The file has to include the realm set through authentication_domain 
                                     and the password in digest format:

                                     user:realm:digest
                                     test:test.com:ce0220efc2dd2fad6185e1f1af5a4327

                                     Password files may be online tools e.g. this generator
                                     http://www.askapache.com/online-tools/htpasswd-generator.
                                     Default: empty
      per_directory_auth_file      - 
      ssi_patterns                 - All files that match ssi_pattern are treated as Server Side Includes (SSI).

                                     SSI is a simple interpreted server-side scripting language which is most 
                                     commonly used to include the contents of another file in a web page. 
                                     It can be useful when it is desirable to include a common piece of code 
                                     throughout a website, for example, headers and footers.

                                     In order for a webpage to recognize an SSI-enabled HTML file, the filename 
                                     should end with a special extension, by default the extension should be 
                                     either .shtml or .shtm. These extensions may be changed using the ssi_pattern 
                                     option.

                                      Unknown SSI directives are silently ignored by CivetWeb. 

                                      The include directive may be used to include the contents of a file or 
                                      the result of running a CGI script. The exec directive is used to execute 
                                      a command on a server, and show the output that would have been printed to 
                                      stdout (the terminal window) otherwise. 

                                      For more information on Server Side Includes, take a look at the Wikipedia: 
                                      http://en.wikipedia.org/wiki/Server_Side_Includes
      access_control_allow_origin  - Access-Control-Allow-Origin header field, used for cross-origin 
                                     resource sharing (CORS). See the Wikipedia page on CORS.
                                     Default: *
      access_control_allow_methods - Access-Control-Allow-Methods header field, used for 
                                     cross-origin resource sharing (CORS) pre-flight requests. 
                                     See the Wikipedia page on CORS.

                                     If set to an empty string, pre-flights will not be supported 
                                     directly by the server, but scripts may still support pre-flights 
                                     by handling the OPTIONS method properly. If set to "*", the 
                                     pre-flight will allow whatever method has been requested. 
                                     If set to a comma separated list of valid HTTP methods, 
                                     the pre-flight will return exactly this list as allowed method. 
                                     If set in any other way, the result is unspecified.
                                     Default: *
      access_control_allow_headers - Access-Control-Allow-Headers header field, used for 
                                     cross-origin resource sharing (CORS) pre-flight requests. 
                                     See the Wikipedia page on CORS.

                                     If set to an empty string, pre-flights will not allow 
                                     additional headers. If set to "*", the pre-flight will 
                                     allow whatever headers have been requested. If set to a 
                                     comma separated list of valid HTTP headers, the pre-flight 
                                     will return exactly this list as allowed headers. 
                                     If set in any other way, the result is unspecified.
                                     Default: *
      error_pages - This option may be used to specify a directory for user 
                    defined error pages. To specify a directory, make sure 
                    the name ends with a backslash (Windows) or slash (Linux, MacOS, ...). 
                    The error pages may be specified for an individual http 
                    status code (e.g., 404 - page requested by the client not found), 
                    a group of http status codes (e.g., 4xx - all client errors) 
                    or all errors. The corresponding error pages must be called 
                    error404.ext, error4xx.ext or error.ext, whereas the file 
                    extension may be one of the extensions specified for the 
                    index_files option.
                    Default: empty
      tcp_nodelay - Enable TCP_NODELAY socket option on client connections.

                    If set the socket option will disable Nagles algorithm 
                    on the connection which means that packets will be sent 
                    as soon as possible instead of waiting for a full buffer 
                    or timeout to occur.

                    0    Keep the default: Nagels algorithm enabled
                    1    Disable Nagels algorithm for all sockets

      static_file_cache_control - Set the Cache-Control header of static files responses. 
                                  The string value will be used directly.

                                  E.g. this config:
                                  no-cache, max-age=31536000

                                  Will result in this header being added:

                                  Cache-Control: no-cache, max-age=31536000

                                  This will take precedence over the static_file_max_age 
                                  option.

                                  Default: No value
      static_file_max_age - Set the maximum time (in seconds) a cache may store a static files.

                            This option will set the Cache-Control: max-age value for static 
                            files. Dynamically generated content, i.e., content created by a 
                            script or callback, must send cache control headers by themselves.

                            A value >0 corresponds to a maximum allowed caching time in seconds. 
                            This value should not exceed one year (RFC 2616, Section 14.21). 
                            A value of 0 will send do not cache at all headers for all static 
                            files. For values <0 and values >31622400, the behaviour is undefined.

                            Default: 3600
      strict_transport_security_max_age - Set the Strict-Transport-Security header, and set the max-age 
                                          value. This instructs web browsers to interact with the server 
                                          only using HTTPS, never by HTTP. If set, it will be sent for 
                                          every request handled directly by the server, except scripts 
                                          (CGI, Lua, ..) and callbacks. They must send HTTP headers on 
                                          their own.

                                          The time is specified in seconds. If this configuration is not 
                                          set, or set to -1, no Strict-Transport-Security header will be 
                                          sent. For values <-1 and values >31622400, the behaviour is 
                                          undefined.
      allow_sendfile_call          - This option can be used to enable or disable the use of the Linux 
                                     sendfile system call. It is only available for Linux systems and 
                                     only affecting HTTP (not HTTPS) connections if throttle is not 
                                     enabled. While using the sendfile call will lead to a performance 
                                     boost for HTTP connections, this call may be broken for some file 
                                     systems and some operating system versions.
                                     Default: yes
      additional_header            - Send additional HTTP response header line for every request. The 
                                     full header line including key and value must be specified, 
                                     excluding the carriage return line feed.
                                     
                                     Example: X-Frame-Options: SAMEORIGIN

                                     Several header lines can be set if seperated with |. All 
                                     specified header lines will be sent. 
      max_request_size             - Size limit for HTTP request headers and header data returned from 
                                     CGI scripts, in Bytes. A buffer of the configured size is pre allocated 
                                     for every worker thread. max_request_size limits the HTTP header, 
                                     including query string and cookies, but it does not affect the HTTP 
                                     body length. The server has to read the entire header from a client 
                                     or from a CGI script, before it is able to process it. In case the 
                                     header is longer than max_request_size, the request is considered 
                                     as invalid or as DoS attack. The configuration value is approximate, 
                                     the real limit might be a few bytes off. The minimum is 1024 (1 kB).
                                     Default: 16384
      allow_index_script_resource  - Index scripts (like index.cgi or index.lua) may have script 
                                     handled resources.

                                     It this feature is activated, that /some/path/file.ext might 
                                     be handled by:

                                     Note: This example is valid, if the default configuration values 
                                     for index_files, cgi_pattern and lua_script_pattern are used.

                                     If this feature is not activated, only the first file 
                                     (/some/path/file.cgi) will be accepted.

                                     Note: This parameter affects only index scripts. A path like 
                                     /here/script.cgi/handle/this.ext will call /here/script.cgi 
                                     with PATH_INFO=/handle/this.ext, no matter if this option 
                                     is set to yes or no.

                                     This feature can be used to completely hide the script extension 
                                     from the URL.

                                     default: no
      duktape_script_patterns      - A pattern for files that are interpreted as JavaScripts by the server. 
                                     Default: **.ssjs$
      lua_preload_file             - This configuration option can be used to specify a Lua script file, 
                                     which is executed before the actual web page script (Lua script, 
                                     Lua server page or Lua websocket). It can be used to modify the Lua 
                                     environment of all web page scripts, e.g., by loading additional 
                                     libraries or defining functions required by all scripts. It may be 
                                     used to achieve backward compatibility by defining obsolete functions 
                                     as well.
                                     Default: none
      lua_script_patterns          - A pattern for files that are interpreted as Lua scripts by the server. 
                                     In contrast to Lua server pages, Lua scripts use plain Lua syntax. 
                                     An example can be found in the test directory.
                                     Default: **.lua$
      lua_server_page_patterns     - Files matching this pattern are treated as Lua server pages. In 
                                     contrast to Lua scripts, the content of a Lua server pages is 
                                     delivered directly to the client. Lua script parts are delimited 
                                     from the standard content by including them between tags. An example 
                                     can be found in the test directory.
                                     Default: **.lp$|**.lsp$
      lua_websocket_patterns       - A pattern for websocket script files that are interpreted as Lua 
                                     scripts by the server.
                                     Default: **.lua$
      lua_background_script        - Experimental feature, and subject to change. Run a Lua script in the 
                                     background, independent from any connection. The script is started
                                     before network access to the server is available. It can be used to 
                                     prepare the document root (e.g., update files, compress files, ...), 
                                     check for external resources, remove old log files, etc.

                                     The Lua state remains open until the server is stopped. In the future, 
                                     some callback functions will be available to notify the script on 
                                     changes of the server state. See example lua script : background.lua.

                                     Additional functions available in background script : sleep, root path, 
                                     script name, is terminated
                                     Default: none
      lua_background_script_params - Can add dynamic parameters to background script. Parameters mapped to 
                                     global 'mg' table 'params' field.
                                     default: param1=1,param2=2
      
                                     If this configuration value is set to no, the websocket server will 
                                     close the connection, once the timeout expires.                          
                                     Default: yes
      case_sensitive               - This option can be uset to enable case URLs for Windows servers. 
                                     It is only available for Windows systems. Windows file systems 
                                     are not case sensitive, but they still store the file name including 
                                     case. If this option is set to yes, the comparison for URIs and 
                                     Windows file names will be case sensitive.                                     
    -->

    <webserver enable="true"
        document_root="/var/lib/vscp/web/html"
        listening_ports="[::]:8888r,[::]:8843s,8884"
        index_files="index.xhtml,index.html,index.htm,index.lp,index.lsp,index.lua,index.cgi,index.shtml,index.php"
        enable_auth_domain_check="false"
        access_log_file="/var/log/vscp/vscpd-access.log"
        error_log_file="/var/log/vscp/vscpd-error.log"
        ssl_certificate=""
        ssl_certificate_chain=""
        ssl_verify_peer="false"
        ssl_ca_path=""
        ssl_ca_file=""
        ssl_verify_depth="9"
        ssl_default_verify_paths="true"
        ssl_cipher_list="DES-CBC3-SHA:AES128-SHA:AES128-GCM-SHA256"
        ssl_protocol_version="3"
        ssl_short_trust="false"
        cgi_interpreter=""
        cgi_patterns="**.cgi$|**.pl$|**.php|**.py"
        cgi_environment=""
        protect_uri=""
        trottle=""
        enable_directory_listing="true"
        enable_keep_alive="false"
        keep_alive_timeout_ms="0"
        access_control_list=""
        extra_mime_types=""
        num_threads="50"
        url_rewrite_patterns=""
        hilde_file_patterns=""
        request_timeout_ms="10000"
        linger_timeout_ms=""
        decode_url="true"
        global_auth_file=""
        per_directory_auth_file=""
        ssi_patterns=""
        access_control_allow_origin="*"
        access_control_allow_methods="*"
        access_control_allow_headers="*"
        error_pages=""
        tcp_nodelay="0"
        static_file_cache_control=""
        static_file_max_age="3600"
        strict_transport_security_max_age=""
        allow_sendfile_call="true"
        additional_header=""
        max_request_size="16384"
        allow_index_script_resource="false"
        duktape_script_patterns="**.ssjs$"
        lua_preload_file=""
        lua_script_patterns="**.lua$"
        lua_server_page_patterns="**.lp$|**.lsp$"
        lua_websocket_patterns="**.lua$"
        lua_background_script=""
        lua_background_script_params=""
     />

    <!--
      Enable disable the REST interface.
    -->
    <restapi enable="true" /> 

    <!--
      Enable disable the websocket interface.

      websocket_root               - In case vscpd is built with Lua and websocket support, 
                                     Lua scripts may be used for websockets as well. Since websockets 
                                     use a different URL scheme (ws, wss) than other http pages 
                                     (http, https), the Lua scripts used for websockets may also be 
                                     served from a different directory. By default, the document_root 
                                     is used as websocket_root as well.
                                     Default: not set = same as document_root
      websocket_timeout_ms         - Timeout for network read and network write operations for websockets, 
                                     WS(S), in milliseconds. If this value is not set, the value of 
                                     request_timeout_ms is used for HTTP(S) as well as for WS(S). 
                                     In case websocket_timeout_ms is set, HTTP(S) and WS(S) can use 
                                     different timeouts.
                                     Default: "30000"
      enable_websocket_ping_pong   - [true/false] - If this configuration value is set to yes, the server 
                                     will send a websocket PING message to a websocket client, once the 
                                     timeout set by websocket_timeout_ms expires. Clients (Web browsers) 
                                     supporting this feature will reply with a PONG message.
                                     Default: "false"
      lua_websocket_pattern        - A pattern for websocket script files that are interpreted as Lua 
                                     scripts by the server.
                                     Default: "**.lua$"
    -->
    <websockets enable="true" 
                websocket_root=""
                websocket_timeout_ms=""
                enable_websocket_ping_pong=""
                lua_websocket_pattern="**.lua$"
    />              
*/

// ----------------------------------------------------------------------------

int depth_setup_parser = 0;

void
startSetupParser(void* data, const char* name, const char** attr)
{
    CWebObj* pObj = (CWebObj*)data;
    if (NULL == pObj) {
        return;
    }

    if ((0 == strcmp(name, "config")) && (0 == depth_setup_parser)) {

        for (int i = 0; attr[i]; i += 2) {

            std::string attribute = attr[i + 1];
            vscp_trim(attribute);

            if (0 == strcasecmp(attr[i], "debug")) {
                if (!attribute.empty()) {
                    if ( "true" == attribute ) {
                        pObj->m_bDebug = true;
                    }
                    else {
                        pObj->m_bDebug = false;
                    }
                }
            } else if (0 == strcasecmp(attr[i], "write")) {
                if (!attribute.empty()) {
                    if ( "true" == attribute ) {
                        pObj->m_bAllowWrite = true;
                    }
                    else {
                        pObj->m_bAllowWrite = false;
                    }
                }
            } else if (0 == strcasecmp(attr[i], "remote-host")) {
                if (!attribute.empty()) {
                    pObj->m_hostRemote = attribute;
                }
            } else if (0 == strcasecmp(attr[i], "remote-port")) {
                if (!attribute.empty()) {
                    pObj->m_portRemote = vscp_readStringValue(attribute);
                }
            } else if (0 == strcasecmp(attr[i], "remote-user")) {
                if (!attribute.empty()) {
                    pObj->m_usernameRemote = attribute;
                }
            } else if (0 == strcasecmp(attr[i], "remote-password")) {
                if (!attribute.empty()) {
                    pObj->m_passwordRemote = attribute;
                }
            } else if (0 == strcasecmp(attr[i], "rxfilter")) {
                if (!attribute.empty()) {
                    if (!vscp_readFilterFromString(&pObj->m_rxfilter,
                                                   attribute)) {
                        syslog(LOG_ERR,
                               "[vscpl2drv-template] Unable to read "
                               "event receive filter.");
                    }
                }
            } else if (0 == strcasecmp(attr[i], "rxmask")) {
                if (!attribute.empty()) {
                    if (!vscp_readMaskFromString(&pObj->m_rxfilter,
                                                 attribute)) {
                        syslog(LOG_ERR,
                               "[vscpl2drv-template] Unable to read "
                               "event receive mask.");
                    }
                }
            } else if (0 == strcasecmp(attr[i], "txfilter")) {
                if (!attribute.empty()) {
                    if (!vscp_readFilterFromString(&pObj->m_txfilter,
                                                   attribute)) {
                        syslog(LOG_ERR,
                               "[vscpl2drv-template] Unable to read "
                               "event transmit filter.");
                    }
                }
            } else if (0 == strcasecmp(attr[i], "txmask")) {
                if (!attribute.empty()) {
                    if (!vscp_readMaskFromString(&pObj->m_txfilter,
                                                 attribute)) {
                        syslog(LOG_ERR,
                               "[vscpl2drv-template] Unable to read "
                               "event transmit mask.");
                    }
                }
            } else if (0 == strcmp(attr[i], "response-timeout")) {
                if (!attribute.empty()) {
                    pObj->m_responseTimeout = vscp_readStringValue(attribute);
                }
            }
        }
    }

    depth_setup_parser++;
}

void
endSetupParser(void* data, const char* name)
{
    depth_setup_parser--;
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
        syslog(LOG_ERR,
               "[vscpl2drv-template] Failed to load configuration file [%s]",
               path.c_str());
    }

    // Start the web server
    try {
        start_webserver();
    }
    catch (...) {
        syslog(LOG_ERR, "Exception when starting web server");
        return false;
    }

    // start the workerthread
    if (pthread_create(&m_pthreadSend, NULL, workerThreadSend, this)) {
        syslog(LOG_ERR,
               "[vscpl2drv-template] Unable to start send worker thread.");
        return false;
    }

    if (pthread_create(&m_pthreadReceive, NULL, workerThreadReceive, this)) {
        syslog(LOG_ERR,
               "[vscpl2drv-template] Unable to start receive worker thread.");
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
//         syslog(
//           LOG_ERR,
//           "[vscpl2drv-template] HLO parser: HLO in-buffer pointer is NULL.");
//         return false;
//     }

//     if (NULL == phlo) {
//         syslog(LOG_ERR,
//                "[vscpl2drv-template] HLO parser: HLO obj pointer is NULL.");
//         return false;
//     }

//     if (!size) {
//         syslog(LOG_ERR,
//                "[vscpl2drv-template] HLO parser: HLO buffer size is zero.");
//         return false;
//     }

//     XML_Parser xmlParser = XML_ParserCreate("UTF-8");
//     XML_SetUserData(xmlParser, this);
//     XML_SetElementHandler(xmlParser, startHLOParser, endHLOParser);

//     void* buf = XML_GetBuffer(xmlParser, XML_BUFF_SIZE);

//     // Copy in the HLO object
//     memcpy(buf, inbuf, size);

//     if (!XML_ParseBuffer(xmlParser, size, size == 0)) {
//         syslog(LOG_ERR, "[vscpl2drv-template] Failed parse XML setup.");
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
//         syslog(LOG_ERR,
//                "[vscpl2drv-template] Failed to open configuration file [%s]",
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
//         syslog(LOG_ERR, "[vscpl2drv-template] Failed parse XML setup.");
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
//         syslog(LOG_ERR,
//                "[vscpl2drv-template] Failed to open configuration file [%s] for write",
//                m_path.c_str());
//         return false;
//     }

//     if ( strlen(buf) != fwrite( buf, sizeof(char), strlen(buf), fp ) ) {
//         syslog(LOG_ERR,
//                "[vscpl2drv-template] Failed to write configuration file [%s] ",
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
//         syslog(LOG_ERR,
//                "[vscpl2drv-template] HLO handler: NULL event pointer.");
//         return false;
//     }

//     CHLO hlo;
//     if (!parseHLO(pEvent->sizeData, pEvent->pdata, &hlo)) {
//         syslog(LOG_ERR, "[vscpl2drv-template] Failed to parse HLO.");
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
        syslog(LOG_ERR,
               "[vscpl2drv-template] Failed to convert event from ex to ev.");
        vscp_deleteEvent(pev);
        return false;
    }
    if (NULL != pev) {
        if (vscp_doLevel2Filter(pev, &m_rxfilter)) {
            pthread_mutex_lock(&m_mutexReceiveQueue);
            m_receiveList.push_back(pev);
            sem_post(&m_semReceiveQueue);
            pthread_mutex_unlock(&m_mutexReceiveQueue);
        } else {
            vscp_deleteEvent(pev);
        }
    } else {
        syslog(LOG_ERR,
               "[vscpl2drv-template] Unable to allocate event storage.");
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
    //     syslog(LOG_ERR,
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

    // syslog(LOG_ERR,
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
    //             syslog(LOG_ERR,
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
    //             syslog(LOG_ERR,
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

    // syslog(LOG_ERR,
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
    //     syslog(LOG_ERR,
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

    // syslog(LOG_ERR,
    //        "%s %s ",
    //        VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
    //        (const char*)"Connect to remote VSCP TCP/IP interface [RECEIVE].");

    // // Set receive filter
    // if (VSCP_ERROR_SUCCESS !=
    //     pObj->m_srvRemoteReceive.doCmdFilter(&pObj->m_rxfilter)) {
    //     syslog(LOG_ERR,
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
    //             syslog(LOG_ERR, "%s %s ", VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
    //                         (const char*)"Lost connection to remote host [Receive].");
    //         }

    //         // Wait before we try to connect again
    //         sleep(VSCP_TCPIPLINK_DEFAULT_RECONNECT_TIME);

    //         if (VSCP_ERROR_SUCCESS !=
    //             pObj->m_srvRemoteReceive.doCmdOpen(pObj->m_hostRemote,
    //                                                 pObj->m_portRemote,
    //                                                 pObj->m_usernameRemote,
    //                                                 pObj->m_passwordRemote)) {
    //             syslog(LOG_ERR,
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

    // syslog(
    //   LOG_ERR,
    //   "%s %s ",
    //   VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
    //   (const char*)"Disconnect from remote VSCP TCP/IP interface [RECEIVE].");

    return NULL;
}
