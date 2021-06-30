# vscpl2drv-websrv

<img src="https://vscp.org/images/logo.png" width="100">

Available for: **Linux** (vscpl2drv-websrv.so), **Windows** (vscpl2drv-websrv.dll)

The vscp2drv-websrv driver act as a web and a websocket(ws1/ws2) and a REST server for VSCP. Users or IoT/m2m devices with different privileges and rights can connect to the exported interface and send/receive VSCP events.

The web server is based on [Civetweb](https://github.com/civetweb/civetweb) and have [Lua](http://www.lua.org/) and [Duktape](https://duktape.org/) and [Sqlite3](https://www.sqlite.org/index.html) and much more enabled. I addition a VSCP rest interface and both of the VSCP websocket interfaces is implemented.

Previously this driver was part of the VSCP daemon but is now separated as a VSCP level II driver to lessen the complexity of the daemon software. The functionality is still the same.

## Install the driver on Linux
You can install the driver using the debian package with

> sudo apt install ./vscpl2drv-websrv_x.y.z.deb

the driver will be installed to _/var/lib/vscp/drivers/level2_

After installing the driver you need to add it to the vscpd.conf file (/etc/vscp/vscpd.conf). See the *configuration* section below.

You also need to set up a configuration file for the driver. If you don't need to dynamically edit the content of this file a good and safe location for this is in the */etc/vscp/* folder alongside the VSCP daemon configuration file.

If you need to do dynamic configuration we recommend that you create the file in the */var/vscp/vscpl2drv-websrv.conf*

A sample configuration file is available in */usr/share/vscpl2drv-websrv* after installation.

## Install the driver on Windows
tbd

## How to build the driver on Linux

- sudo apt update && sudo apt -y upgrade
- sudo apt install build-essential
- sudo apt install git
- sudo git clone https://github.com/grodansparadis/vscp.git
- sudo git clone https://github.com/grodansparadis/vscpl2drv-websrv.git
- sudo apt install pandoc           (comment: optional)
- sudo apt install cmake
- sudo apt install libexpat-dev
- sudo apt install libssl-dev
- sudo apt install rpm              (comment: only if you want to create install packages)
- cd vscpl2drv-websrv
- mkdir build
- cd build
- cmake ..
- make
- make install
- sudo cpack ..                     (comment: only if you want to create install packages)

Install of _pandoc_ is only needed if man pages needs to be rebuilt. This is normally already done and available in the repository.

Default install folder when you build from source is */usr/local/lib*. You can change this with the --prefix option in the build step. For example *--prefix /usr* to install to */usr/lib* as the debian install

## How to build the driver on Windows

### Install the vcpkg package manager

You need the vcpkg package manager on windows. Install it with

```bash
git clone https://github.com/microsoft/vcpkg.git
```

then go into the folder

```bash
cd vcpkg
```

Run the vcpkg bootstrapper command

```bash
bootstrap-vcpkg.bat
```

The process is described in detail [here](https://docs.microsoft.com/en-us/cpp/build/install-vcpkg?view=msvc-160&tabs=windows)

To [integrate with Visual Studio](https://docs.microsoft.com/en-us/cpp/build/integrate-vcpkg?view=msvc-160) run

```bash
vcpkg integrate install
```

Install the required libs

```bash
vcpkg install pthread:x64-windows
vcpkg install expat:x64-windows
vcpkg install openssl:x64-windows
```

Full usage is describe [here](https://docs.microsoft.com/en-us/cpp/build/manage-libraries-with-vcpkg?view=msvc-160&tabs=windows)

### Get the source

You need to checkout the VSCP main repository code in addition to the driver repository. You do this with

```bash
  git clone https://github.com/grodansparadis/vscp.git
  cd vscp
  git checkout development
``` 

and the vscpl2drv-websrv source code

```bash
git clone https://github.com/grodansparadis/vscpl2drv-websrv.git
```

If you check out both at the same directory level the *-DVSCP_PATH=path-vscp-repository* in next step is not needed.

### Build the driver

Build as usual but use

```bash
cd vscpl2drv-websrv
mkdir build
cd build
cmake .. -CMAKE_BUILD_TYPE=Release|Debug -DCMAKE_TOOLCHAIN_FILE=E:\src\vcpkg\scripts\buildsystems\vcpkg.cmake -DVSCP_PATH=path-vscp-repository
```

The **CMAKE_TOOLCHAIN_FILE** path may be different in your case

Note that *Release|Debug* should be either *Release* or *Debug*

The windows build files can now be found in the build folder and all needed files to run the project can  after build - be found in build/release or build/Debug depending on CMAKE_BUILD_TYPE setting.

Building and configuration is simplified with VS Code installed. Configure/build/run can be done (se lower toolbar). Using VS Code it ,ay be useful to add

```json
"cmake.configureSettings": {
   "CMAKE_BUILD_TYPE": "${buildType}"
}
``` 

to your settings.json file.

To build at the command prompt use

```bash
msbuild vscp-works-qt.sln
```

Note that you must have a *developer command prompt*

### Build deploy packages 

Install NSIS from [this site](https://sourceforge.net/projects/nsis/).

Run 

```bash
cpack ...
```
 
in the build folder.



## Configuration

### VSCP daemon configuration for driver

The VSCP daemon configuration is (normally) located at */etc/vscp/vscpd.conf*. To use the vscpl2drv-websrv.so driver there must be an entry in the

```
> <level2driver enable="true">
```

section on the following format

```xml
<!-- Level II TCP/IP Server -->
<driver enable="true"
    name="vscp-tcpip-srv"
    path-driver="/usr/lib/vscp/drivers/level2/vscpl2drv-websrv.so"
    path-config="/etc/vscp/vscpl2drv-websrv.json"
    guid="FF:FF:FF:FF:FF:FF:FF:FC:88:99:AA:BB:CC:DD:EE:FF"
</driver>
```

#### enable
Set enable to "true" if the driver should be loaded.

#### name
This is the name of the driver. Used when referring to it in different interfaces.

#### path
This is the path to the driver. If you install from a Debian package this will be */usr/bin/vscpl2drv-websrv.so* and if you build and install the driver yourself it will be */usr/local/bin/vscpl2drv-websrv.so* or a custom location if you configured that.

#### guid
All level II drivers **must have** a unique GUID. There is many ways to obtain this GUID, Read more [here](https://grodansparadis.gitbooks.io/the-vscp-specification/vscp_globally_unique_identifiers.html).



### vscpl2drv-websrv driver configuration file

When the VSCP daemon starts up the configuration for the driver is read from a JSON file specified by the path set in the driver configuration of the VSCP daemon. Usually this file is locatd at */etc/vscp/vscpl2drv-websrv*. 

If the **write** parameter (see information below) is set to "true" the above location is a bad choice as the VSCP daemon will not be able to write to this location. A better location in this case is */var/lib/vscp/drivers/level2/vscpl2drv-websrv.json* or some other writable location of choice.

The configuration file have the following format

```json
{
    "write" : false,
    "debug" : false,
    "key-file": "/var/vscp/.key",
    "path-users" : "/etc/vscp/users.json",
    "encryption" : "none|aes128|aes192|aes256",

    "logging": { 
        "console-enable": true,
        "console-level": "trace",
        "console-pattern": "[vcpl2drv-websrv] [%^%l%$] %v",
        "file-enable": true,
        "file-log-level": "off|critical|error|warn|info|debug|trace",
        "file-log-path" : "/var/log/vscp/vscpl1drv-websrv.log",
        "file-log-pattern": "[vcpl2drv-websrv] [%^%l%$] %v",
        "file-log-max-size": 50000,
        "file-log-max-files": 7
    }, 
    "web" : {
        "enable" : true,
        "document-root": "/var/lib/vscp/web/html",
        "listening-ports" : [
            "[::]:8888r",
            "[::]:8843s",
            "8884"
        ],
        "authentication-domain": "mydomain.com",
        "enable-auth-domain-check" : false,
        "index-files" : [
            "index.xhtml",
            "index.html",
            "index.htm",
            "index.lp",
            "index.lsp",
            "index.lua",
            "index.cgi",
            "index.shtml",
            "index.php"
        ],        
        "access-log-file" : "/var/log/vscp/vscpl2drv-websrv-access.log",
        "error-log-file" : "/var/log/vscp/vscpl2drv-websrv-error.log",
        "protect-uri" : "",
        "throttle" : "",
        "enable-directory-listing" : true,
        "enable-keep-alive" : false,
        "keep-alive-timeout-ms" : 0,
        "access-control-list" : "",
        "extra-mime-types" : "",
        "num-threads" : 50,
        "url-rewrite-patterns" : "",
        "hide-file-patterns" : "",
        "request-timeout-ms" : 10000,
        "linger-timeout-ms" : 0,
        "decode-url" : true,
        "global-auth-file" : "",
        "put-delete-auth-file" : "",
        "ssi-patterns" : "",
        "access-control-allow-origin" : "*",
        "access-control-allow-methods" : "*",
        "access-control-allow-headers" : "*",
        "error-pages" : "",
        "tcp-nodelay" : 0,
        "static-file-cache-control" : "",
        "static-file-max-age" : 3600,
        "strict-transport-security-max-age" : -1,
        "allow-sendfile-call" : true,
        "additional-header" : "",
        "max-request-size" : 16384,
        "allow-index-script-resource" : false,
        "tls": {
            "certificate" : "/srv/vscp/certs/tcpip_server.pem",
            "certificate-chain" : "",
            "verify-peer" : false,
            "ca-path" : "",
            "ca-file" : "",
            "verify-depth" : 9,
            "default-verify-paths" : true,
            "cipher-list" : "DES-CBC3-SHA:AES128-SHA:AES128-GCM-SHA256",
            "protocol-version" : 3,
            "ssl_cache_timeout": -1,
            "short-trust" : false
        },
        "cgi" : {
            "cgi-interpreter" : "",
            "cgi-patterns" : "**.cgi$|**.pl$|**.php|**.py",
            "cgi-environment" : ""    
        },
        "duktape" : {
            "duktape-script-patterns" : "**.ssjs$"
        },
        "lua" : {
            "lua-preload-file" : "",
            "lua-script-patterns" : "**.lua$",
            "lua-server-page_patterns" : "**.lp$|**.lsp$",
            "lua-websocket-patterns" : "**.lua$",
            "lua-background-script" : "",
            "lua-background-script-params" : ""
        }

    },   
    "restapi" : {
        "enable" : true
    },
    "websocket" : {
        "enable" : true,
        "websocket-root" : "",
        "websocket-timeout-ms" : 2000,
        "enable-websocket-ping-pong" : false
    },

    
    "filter" : {
        "in-filter" : "incoming filter on string form",
        "in-mask" : "incoming mask on string form",
        "out-filter" : "outgoing filter on string form",
        "out-mask" : "outgoing mask on string form"
    }
    
}
```

#### write
If write is true changes to the configuration file will be possible to save to disk. That is settings you do at runtime that can be saved and after that be persistent. The safest location for a configuration file is in the VSCP configuration folder */etc/vscp/*, but dynamic saves are not allowed to save data to this location if you don't run the VSCP daemon as root (which you should not). Next best place is to use the folder */var/lib/vscp/drivername/configure.json*. This folder is created and a default configuration is written here when the driver is installed.

If you never intend to change driver parameters during runtime consider moving the configuration file to the VSCP daemon configuration folder.

Currently this option is not enabled and is always set to false.

#### debug
Extra debugging information will be issued if you set this configuration value to true.

#### key-file
This is a path to a file that holds a 256-bit encryption value. The file should contain a 32 byte hexadecimal string.

#### path-users

This is the path to a file that contains access information for users of the webserver, the ws1 and ws2 web-interfaces and the REST interface.

This file have the same format as and is shared by several VSCP drivers. The content is defined [here](https://grodansparadis.github.io/vscp-doc-spec/#/./appendix_a_users). 


#### **Logging**

Options for driver logging is set here.

##### console-enable 
Set to _true_ to log to the console.

##### console-level
Logging level for console log. Set to one of "off | critical | error | warn | info | debug | trace". 

##### console-pattern
The logging pattern for the console. The default is

```
"[vcpl2drv-websrv] [%^%l%$] %v"
```
Patterns are described [here](https://spdlog.docsforge.com/v1.x/3.custom-formatting/#pattern-flags).

##### file-enable 
Set to _true_ to log to the console.

##### file-level
Set to one of "off | critical | error | warn | info | debug | trace" to set log level.

##### file-path" : "path to log file",
This is a writable path to a file that will get log information written to it. This can be a valuable to have if things does not behave as expected.

##### file-pattern
The logging pattern for the console. The default is

```
"[vcpl2drv-websrv] [%^%l%$] %v"
```
Patterns are described [here](https://spdlog.docsforge.com/v1.x/3.custom-formatting/#pattern-flags).

##### file-max-size
Max size for log file before it will rotate and a new file is created. Default is 5 Mb.

##### file-max-files
Max number of log files to keep. Default is 7

#### **Web**

Settings for the web server interface. Most of the settings are directly from [Civetweb configuration values](https://github.com/civetweb/civetweb/blob/master/docs/UserManual.md). Some default may have been changed. A dash is used for the driver while Civetweb use underscore.

##### enable

Set to _true_ to enable the web interface,

##### document-root

This is the root folder  for web files. On Linux it default to _/var/lib/vscp/web/html_

##### listening-ports

This is a list of the ports that the web server will listen on. It can either be given as a JSON list on the following form

```json
"listening-ports" : [
    "[::]:8888r",
    "[::]:8843s",
    "8884"
],
```

or as a comma separated string

```json
"listening-ports" : "[::]:8888r,[::]:8843s,8884"
```

 - A _s_ after the port means the port is a secure TLS port.
 - A _r_ after the port means the port will redirect to a secure port.

 For a complete description go [here](https://github.com/civetweb/civetweb/blob/master/docs/UserManual.md#listening_ports-8080).

##### auth-domain
Authorization realm used for HTTP digest authentication. This domain is used in the encoding of the .htpasswd authorization files as well. Changing the domain retroactively will render the existing passwords useless.

For a complete description go [here](https://github.com/civetweb/civetweb/blob/master/docs/UserManual.md#authentication_domain-mydomaincom)

##### index-files

Directory index files. If more than one of the listed files are found in a directory the first mentioned is used.

Can be set as a comma separated string or as a JSON list.

For a complete description go [here](https://github.com/civetweb/civetweb/blob/master/docs/UserManual.md#index_files-indexxhtmlindexhtmlindexhtmindexcgiindexshtmlindexphp)

##### access-log-file

Path to a file for access logs. Either full path, or relative to the current working directory. If not defined, then accesses are not logged. Default is to log accesses to _/var/log/vscp/vscpl2drv-websrv-access.log_ on Linux.

##### error-log-file

Path to a file for error logs. Either full path, or relative to the current working directory. If not defined, then errors are not logged.
Default is to log accesses to _/var/log/vscp/vscpl2drv-websrv-error.log_ on Linux.

##### protect-uri

Comma separated list of URI=PATH pairs, specifying that given URIs must be protected with password files specified by PATH. All Paths must be full file paths.

Can be given as a comma separated string or as a JSON list.

##### throttle

Limit download speed for clients. Default is none defined.

For a complete description go [here](https://github.com/civetweb/civetweb/blob/master/docs/UserManual.md#throttle)

##### enable-directory-listing

Files and folders in a directory will be listed if set to _true_ and no index file is present.  Default is **true**.

##### enable-keep-alive

Allows clients to reuse TCP connection for subsequent HTTP requests, which improves performance. For this to work when using request handlers it is important to add the correct Content-Length HTTP header for each request. If this is forgotten the client will time out.

Note: If you set keep_alive to yes, you should set keep_alive_timeout_ms to some value > 0 (e.g. 500). If you set keep_alive to no, you should set keep_alive_timeout_ms to 0. Currently, this is done as a default value, but this configuration is redundant. In a future version, the keep_alive configuration option might be removed and automatically set to yes if a timeout > 0 is set.

Default is **false**.

##### keep-alive-timeout-ms

Idle timeout between two requests in one keep-alive connection. If keep alive is enabled, multiple requests using the same connection are possible. This reduces the overhead for opening and closing connections when loading several resources from one server, but it also blocks one port and one thread at the server during the lifetime of this connection. Unfortunately, browsers do not close the keep-alive connection after loading all resources required to show a website. The server closes a keep-alive connection, if there is no additional request from the client during this timeout.

Note: if enable_keep_alive is set to no the value of keep_alive_timeout_ms should be set to 0, if enable_keep_alive is set to yes, the value of keep_alive_timeout_ms must be >0. Currently keep_alive_timeout_ms is ignored if enable_keep_alive is no, but future versions may drop the enable_keep_alive configuration value and automatically use keep-alive if keep_alive_timeout_ms is not 0.

More info can be found [here](https://github.com/civetweb/civetweb/blob/master/docs/UserManual.md#keep_alive_timeout_ms-500-or-0)

Default is **500/0**

##### access-control-list

An Access Control List (ACL) allows restrictions to be put on the list of IP addresses which have access to the web server.

More info can be found [here](https://github.com/civetweb/civetweb/blob/master/docs/UserManual.md#access_control_list)

Default is empty.

##### extra-mime-types

Comma separated list of extra mime types, on the form _extension1=type1,exten-sion2=type2,...._  More info is [here](https://github.com/civetweb/civetweb/blob/master/docs/UserManual.md#extra_mime_types)

Default is empty.

##### num-threads
Default is **50**.

##### url-rewrite-patterns

Comma-separated list of URL rewrites in the form of _uri_pattern=file_or_directory_path_. More information is [here](https://github.com/civetweb/civetweb/blob/master/docs/UserManual.md#url_rewrite_patterns)

Default is empty.

##### hide-file-patterns

A pattern for the files to hide. More info can be found [here](https://github.com/civetweb/civetweb/blob/master/docs/UserManual.md#hide_files_patterns).

Default is empty.

##### request-timeout-ms
Timeout for network read and network write operations, in milliseconds. If a client intends to keep long-running connection, either increase this value or (better) use keep-alive messages.

Default is **10000**.

##### linger-timeout-ms

Set TCP socket linger timeout before closing sockets (SO_LINGER option). The configured value is a timeout in milliseconds. Setting the value to 0 will yield in abortive close (if the socket is closed from the server side). Setting the value to -1 will turn off linger. If the value is not set (or set to -2), CivetWeb will not set the linger option at all.

Note: For consistency with other timeout configurations, the value is configured in milliseconds. However, the TCP socket layer usually only offers a timeout in seconds, so the value should be an integer multiple of 1000.

Default is **0**.

##### decode-url

URL encoded request strings are decoded in the server, unless it is disabled by setting this option to no.

Default is **true**.

##### global-auth-file

Path to a global passwords file, either full path or relative to the current working directory. More info can be found [here](https://github.com/civetweb/civetweb/blob/master/docs/UserManual.md#global_auth_file).

Default is empty.

##### put-delete-auth-file

Passwords file for PUT and DELETE requests. Without a password file, it will not be possible to PUT new files to the server or DELETE existing ones. PUT and DELETE requests might still be handled by Lua scripts and CGI paged.

Default is empty.

##### ssi-pattern

All files that match ssi_pattern are treated as Server Side Includes (SSI).

More iinfo is [here](https://github.com/civetweb/civetweb/blob/master/docs/UserManual.md#ssi_pattern-shtmlshtm)

Default is "**.shtml$|**.shtm$".

##### access-control-allow-origin

Access-Control-Allow-Origin header field, used for cross-origin resource sharing (CORS). See the [Wikipedia page on CORS](http://en.wikipedia.org/wiki/Cross-origin_resource_sharing).

Default is "*".

##### access-control-allow-methods

Access-Control-Allow-Methods header field, used for cross-origin resource sharing (CORS) pre-flight requests. See the [Wikipedia page on CORS](http://en.wikipedia.org/wiki/Cross-origin_resource_sharing).

More information is [here](https://github.com/civetweb/civetweb/blob/master/docs/UserManual.md#access_control_allow_methods-).

Default is "*".

##### access-control-allow-headers

Access-Control-Allow-Headers header field, used for cross-origin resource sharing (CORS) pre-flight requests. See the [Wikipedia page on CORS](http://en.wikipedia.org/wiki/Cross-origin_resource_sharing).

More information is [here](https://github.com/civetweb/civetweb/blob/master/docs/UserManual.md#access_control_allow_methods-)

Default is "*".

##### error-pages

This option may be used to specify a directory for user defined error pages. To specify a directory, make sure the name ends with a backslash (Windows) or slash (Linux, MacOS, ...). The error pages may be specified for an individual http status code (e.g., 404 - page requested by the client not found), a group of http status codes (e.g., 4xx - all client errors) or all errors. The corresponding error pages must be called error404.ext, error4xx.ext or error.ext, whereas the file extension may be one of the extensions specified for the index_files option. See the [Wikipedia page on HTTP status codes](http://en.wikipedia.org/wiki/HTTP_status_code).

Default is empty.

##### tcp-nodelay

Enable **TCP_NODELAY** socket option on client connections.

More information is [here](https://github.com/civetweb/civetweb/blob/master/docs/UserManual.md#tcp_nodelay-0).

Default is *0*.

##### static-file-cache-control

Set the Cache-Control header of static files responses. More information is [here](https://github.com/civetweb/civetweb/blob/master/docs/UserManual.md#static_file_cache_control).

Default is empty.

##### static-file-max-age

Set the maximum time (in seconds) a cache may store a static files. More information is [here](https://github.com/civetweb/civetweb/blob/master/docs/UserManual.md#static_file_max_age-3600).

Default is **3600**.

##### strict-transport-security-max-age

Set the Strict-Transport-Security header, and set the max-age value. This instructs web browsers to interact with the server only using HTTPS, never by HTTP. If set, it will be sent for every request handled directly by the server, except scripts (CGI, Lua, ..) and callbacks. They must send HTTP headers on their own.

The time is specified in seconds. If this configuration is not set, or set to -1, no Strict-Transport-Security header will be sent. For values <-1 and values >31622400, the behavior is undefined.

Default is **-1**.

##### allow-sendfile-call

This option can be used to enable or disable the use of the Linux sendfile system call. It is only available for Linux systems and only affecting HTTP (not HTTPS) connections if throttle is not enabled. While using the sendfile call will lead to a performance boost for HTTP connections, this call may be broken for some file systems and some operating system versions.

Default is **true**.

##### additional-header

Send additional HTTP response header line for every request. The full header line including key and value must be specified, excluding the carriage return line feed.

Example (used as command line option): -additional_header "X-Frame-Options: SAMEORIGIN"

This option can be specified multiple times. All specified header lines will be sent.

Default is empty.

##### max-request-size

Size limit for HTTP request headers and header data returned from CGI scripts, in Bytes. A buffer of the configured size is pre allocated for every worker thread. max_request_size limits the HTTP header, including query string and cookies, but it does not affect the HTTP body length. The server has to read the entire header from a client or from a CGI script, before it is able to process it. In case the header is longer than max_request_size, the request is considered as invalid or as DoS attack. The configuration value is approximate, the real limit might be a few bytes off. The minimum is 1024 (1 kB).

Default is **16384**.

##### allow-index-script-resource

Index scripts (like _index.cgi_ or _index.lua_) may have script handled resources. More information is [here](https://github.com/civetweb/civetweb/blob/master/docs/UserManual.md#allow_index_script_resource-no).

Default is **false**.

##### "tls": {

###### certificate

Path to the SSL certificate file. This option is only required when at least one of the listening ports is SSL. The file must be in PEM format, and it must have both, private key and certificate. An example certificate is [here](https://github.com/civetweb/civetweb/blob/master/resources/ssl_cert.pem).

Default is **"/srv/vscp/certs/web_server.pem"**.  

###### certificate-chain

Path to an SSL certificate chain file. As a default, the ssl_certificate file is used.

Default is empty.

###### cipher-list

List of ciphers to present to the client. Entries should be separated by colons, commas or spaces. More information is [here](https://github.com/civetweb/civetweb/blob/master/docs/UserManual.md#ssl_cipher_list).

Default is **"DES-CBC3-SHA:AES128-SHA:AES128-GCM-SHA256"**.

###### default-verify-paths

Loads default trusted certificates locations set at openssl compile time.

Default is **true**.

###### protocol-version

Sets the minimal accepted version of SSL/TLS protocol. More information is [here](https://github.com/civetweb/civetweb/blob/master/docs/UserManual.md#ssl_protocol_version-4).

Default is **4**.

###### short-trust

Enables the use of short lived certificates. This will allow for the certificates and keys specified in ssl_certificate, ssl_ca_file and ssl_ca_path to be exchanged and reloaded while the server is running.

In an automated environment it is advised to first write the new pem file to a different filename and then to rename it to the configured pem file name to increase performance while swapping the certificate.

Disk IO performance can be improved when keeping the certificates and keys stored on a tmpfs (linux) on a system with very high throughput.

Default is **false**.

###### verify-depth

Sets maximum depth of certificate chain. If client's certificate chain is longer than the depth set here connection is refused.

Default is **9**.

###### verify-peer

Enable client's certificate verification by the server.

Default is **false**.

###### ca-path

Name of a directory containing trusted CA certificates. Each file in the directory must contain only a single CA certificate. The files must be named by the subject name’s hash and an extension of “.0”. If there is more than one certificate with the same subject name they should have extensions ".0", ".1", ".2" and so on respectively.

Default is empty.

###### ca-file

Path to a .pem file containing trusted certificates. The file may contain more than one certificate.

Default is empty.

###### ssl_cache_timeout

Allow caching of SSL/TLS sessions, so HTTPS connection from the same client to the same server can be established faster. A configuration value >0 activates session caching. The configuration value is the maximum lifetime of a cached session in seconds. The default is to deactivated session caching.

Default is **-1**.

##### cgi" : {

###### cgi-interpreter

Path to an executable to use as CGI interpreter for all CGI scripts regardless of the script file extension. If this option is not set (which is the default), CivetWeb looks at first line of a CGI script, [shebang line](http://en.wikipedia.org/wiki/Shebang_(Unix\)), for an interpreter (not only on Linux and Mac but also for Windows).

For example, if both PHP and Perl CGIs are used, then #!/path/to/php-cgi.exe and #!/path/to/perl.exe must be first lines of the respective CGI scripts. Note that paths should be either full file paths, or file paths relative to the current working directory of the CivetWeb server. If CivetWeb is started by mouse double-click on Windows, the current working directory is the directory where the CivetWeb executable is located.

If all CGIs use the same interpreter, for example they are all PHP, it is more efficient to set cgi_interpreter to the path to php-cgi.exe. The shebang line in the CGI scripts can be omitted in this case. Note that PHP scripts must use php-cgi.exe as executable, not php.exe.

Default is empty.

###### cgi-patterns

All files that match cgi_pattern are treated as CGI files. The default pattern allows CGI files be anywhere. More information is [here](https://github.com/civetweb/civetweb/blob/master/docs/UserManual.md#cgi_pattern-cgiplphp).

Default is **"**.cgi$|**.pl$|**.php|**.py"**.

###### cgi-environment

Extra environment variables to be passed to the CGI script in addition to standard ones. The list must be comma-separated list of name=value pairs, like this: _VARIABLE1=VALUE1,VARIABLE2=VALUE2_.

Default is empty.

##### duktape" : {

###### duktape-script-patterns

Files with this extension are Duktape server side scripts.

Default is **"**.ssjs$"**.

##### lua" : {

###### lua-preload-file

This configuration option can be used to specify a Lua script file, which is executed before the actual web page script (Lua script, Lua server page or Lua websocket). It can be used to modify the Lua environment of all web page scripts, e.g., by loading additional libraries or defining functions required by all scripts. It may be used to achieve backward compatibility by defining obsolete functions as well.

Default is empty.

###### lua-script-patterns

A pattern for files that are interpreted as Lua scripts by the server. In contrast to Lua server pages, Lua scripts use plain Lua syntax. An example can be found in the test directory.

Default is **"**.lua$"**.

###### lua-server-page_patterns

Files matching this pattern are treated as Lua server pages. In contrast to Lua scripts, the content of a Lua server pages is delivered directly to the client. Lua script parts are delimited from the standard content by including them between tags. An example can be found in the test directory.

Default is **"**.lp$|**.lsp$"**.

###### lua-websocket-patterns

A pattern for websocket script files that are interpreted as Lua scripts by the server.

Default is **"**.lua$"**.

###### lua-background-script

Run a Lua script in the background, independent from any connection. The script is started before network access to the server is available. It can be used to prepare the document root (e.g., update files, compress files, ...), check for external resources, remove old log files, etc.

The script can define callbacks to be notified when the server starts or stops. Furthermore, it can be used for log filtering or formatting. The Lua state remains open until the server is stopped.

For a detailed descriotion of available Lua callbacks see section "Lua background script" below.

Default is empty.

###### lua-background-script-params

Can add dynamic parameters to background script. Parameters mapped into 'mg.params' as table. Example: _paramName1=paramValue1,paramName2=2_

Default is empty.

#### restapi

Settings for the VSCP REST api.

##### enable

Set to true to enable the VSCP REST API.

Default is **true**.

#### websocket

##### enable

Set to true to enable the VSCP ws1 and ws2 websocket API's.

Default is **true**.

##### root

Set the websocket root folder. Not used by the driver. It instead uses "/ws1" for VSCP ws1 websocket protocol and "/ws2" for VSCP ws2 protocol.

Default is empty.

##### timeout-ms

Timeout for websocket subsystem in ms.

Default is **2000**, i.e. 2 seconds.

##### enable-ping-pong

Enable websocket ping-pong functionality.

Default is **false**

#### filter

##### Filters

###### filter
Main filter for incoming and outgoing events. Default is to send and receive all events. The truth table for VSCP filter/masks is described [here](https://grodansparadis.github.io/vscp-doc-spec/#/./vscp_decision_matrix?id=truth-table-for-filtermask).

Filter and mask is a way to select which events is received by the driver. A filter have the following format

> priority,vscpclass,vscptype,guid

All values can be give in decimal or hexadecimal (preceded number with '0x'). GUID is always given i hexadecimal (without preceded '0x').

**Default**: setting is

> 0,0,0,00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00

Read the [vscpd manual](http://grodansparadis.github.io/vscp/#/) for more information about how filter/masks work.

The default filter/mask pair means that all events are received by the driver.

###### mask
Filter and mask is a way to select which events is received by the driver. A mask have the following format

> priority,vscpclass,vscptype,guid

All values can be give in decimal or hexadecimal (preceded number with '0x'). GUID is always given i hexadecimal (without preceded '0x').

The mask have a binary one ('1') in the but position of the filter that should have a specific value and zero ('0') for a don't care bit.

Default setting is

> 0,0,0,00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00

Read the vscpd manual for more information about how filter/masks work.

The default filter/mask pair means that all events are received by the driver.

##### in-filter
Incoming filter on string form. The string filter has the form _"filter-priority, filter-class, 
    filter-type, filter-GUID"_

##### in-mask
Incoming mask on string form. The string mask has the form _"mask-priority, 
    mask-class, mask-type, mask-GUID”_.

##### out-filter
Outgoing filter on string form. The string filter has the form _"filter-priority, filter-class, 
    filter-type, filter-GUID"_

##### out-mask
Outgoing mask on string form. The string mask has the form _"mask-priority, 
    mask-class, mask-type, mask-GUID”_.

---


##### filter


##### mask
Filter and mask is a way to select which events is received by the driver. A mask have the following format

> priority,vscpclass,vscptype,guid

All values can be give in decimal or hexadecimal (preceded number with '0x'). GUID is always given i hexadecimal (without preceded '0x').

The mask have a binary one ('1') in the but position of the filter that should have a specific value and zero ('0') for a don't care bit.

Default setting is

> 0,0,0,00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00

Read the vscpd manual for more information about how filter/masks work.

The default filter/mask pair means that all events are received by the driver.


## Using the vscpl2drv-websrv driver

The [vscp-ux](https://github.com/grodansparadis/vscp-ux) contains a set of pages and script to test the web/websocket and REST functionality provided by this driver. Instructions on how to install is on the repository.

There is currently no documentation for LUA and Diktape and the rest of the functionality. Until this documentation is in place please check the version 14.0 documentation. There is also some information in the [Civetweb project](https://github.com/civetweb/civetweb) which is the base code for the webserver functionality.

---

## Other sources with information

  * The VSCP site - https://www.vscp.org
  * The VSCP document site - https://docs.vscp.org/
  * VSCP discussions - https://github.com/grodansparadis/vscp/discussions
