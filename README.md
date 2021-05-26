# vscpl2drv-websrv

<img src="https://vscp.org/images/logo.png" width="100">

    Available for: Linux, Windows
    Driver Linux: vscpl2drv-websrv.so
    Driver Windows: vscpl2drv-websrv.dll

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
        "per-directory-auth-file" : "",
        "ssi-patterns" : "",
        "access-control-allow-origin" : "*",
        "access-control-allow-methods" : "*",
        "access-control-allow-headers" : "*",
        "error-pages" : "",
        "tcp-nodelay" : 0,
        "static-file-cache-control" : "",
        "static-file-max-age" : 3600,
        "strict-transport-security-max-age" : 0,
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


#### Logging

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

#### web

Settings for the web interface.

##### enable

Set to _true_ to enable the web interface

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

-------------------------------------------------------------

##### interface
Set the interface to listen on. Default is: *tcp://localhost:9598*. The interface is either secure (TLS) or insecure. It is not possible to define interfaces that accept connections of both types.

if "tcp:// part is omitted the content is treated as it was present.

If port is omitted, default 9598 is used.

For TLS/SSL use prefix "stcp://"

##### auth-domain
The authentication domain. In reality this is an arbitrary string that is used when calculating md5 checksums. In this case the checksum is calculated over "user:auth-domain-password"

##### path-users
The user database is separated from the configuration file for security reasons and should be stored in a folder that is only readable by the user the VSCP daemon is run as. Usually this is the user __vscp__.

The format for the user file is specified below.

##### response-timeout
Response timeout in milliseconds. 

##### encryption
Response and commands from/to the tcp/ip link server can be encrypted using AES-128, AES-192 or AES-256. Set here as

"none|aes128|aes192|aes256"

**Default**: is no encryption.

##### filter
Filter and mask is a way to select which events is received by the driver. A filter have the following format

> priority,vscpclass,vscptype,guid

All values can be give in decimal or hexadecimal (preceded number with '0x'). GUID is always given i hexadecimal (without preceded '0x').

**Default**: setting is

> 0,0,0,00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00

Read the [vscpd manual](http://grodansparadis.github.io/vscp/#/) for more information about how filter/masks work.

The default filter/mask pair means that all events are received by the driver.

##### mask
Filter and mask is a way to select which events is received by the driver. A mask have the following format

> priority,vscpclass,vscptype,guid

All values can be give in decimal or hexadecimal (preceded number with '0x'). GUID is always given i hexadecimal (without preceded '0x').

The mask have a binary one ('1') in the but position of the filter that should have a specific value and zero ('0') for a don't care bit.

Default setting is

> 0,0,0,00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00

Read the vscpd manual for more information about how filter/masks work.

The default filter/mask pair means that all events are received by the driver.

##### ssl_certificate
Path to SSL certificate file. This option is only required when at least one of the listening_ports is SSL The file must be in PEM format, and it must have both private key and certificate, see for example ssl_cert.pem. If this option is set, then the webserver serves SSL connections on the port set up to listen on.

**Default**: /srv/vscp/certs/server.pem

##### ssl_certificate_chain
T.B.D.

##### ssl_verify_peer
Enable client's certificate verification by the server.

**Default**: false

##### ssl_ca_path
Name of a directory containing trusted CA certificates for peers. Each file in the directory must contain only a single CA certificate. The files must be named by the subject name’s hash and an extension of “.0”. If there is more than one certificate with the same subject name they should have extensions ".0", ".1", ".2" and so on respectively.

##### ssl_ca_file"
Path to a .pem file containing trusted certificates for peers. The file may contain more than one certificate.

##### ssl_verify_depth
Sets maximum depth of certificate chain. If client's certificate chain is longer than the depth set here connection is refused.

**Default**: 9

##### ssl_default_verify_paths
Loads default trusted certificates locations set at openssl compile time.

**Default**: true

##### ssl_cipher_list
List of ciphers to present to the client. Entries should be separated by colons, commas or spaces.

| Selection	| Description |
| ========= | =========== |
| ALL |	All available ciphers |
| ALL:!eNULL | All ciphers excluding NULL ciphers |
| AES128:!MD5 | AES 128 with digests other than MD5 |

See [this entry in OpenSSL documentation](https://www.openssl.org/docs/manmaster/apps/ciphers.html) for full list of options and additional examples.

**Default**: "DES-CBC3-SHA:AES128-SHA:AES128-GCM-SHA256",

##### ssl_protocol_version
Sets the minimal accepted version of SSL/TLS protocol according to the table:

| Selected protocols | setting |
| ================== | ======= |
| SSL2+SSL3+TLS1.0+TLS1.1+TLS1.2 | 0 |
| SSL3+TLS1.0+TLS1.1+TLS1.2 | 1 |
| TLS1.0+TLS1.1+TLS1.2 | 2 |
| TLS1.1+TLS1.2	| 3 |
| TLS1.2 | 4 |

**Default**: 4.

##### ssl_short_trust
Enables the use of short lived certificates. This will allow for the certificates and keys specified in ssl_certificate, ssl_ca_file and ssl_ca_path to be exchanged and reloaded while the server is running.

In an automated environment it is advised to first write the new pem file to a different filename and then to rename it to the configured pem file name to increase performance while swapping the certificate.

Disk IO performance can be improved when keeping the certificates and keys stored on a tmpfs (linux) on a system with very high throughput.

**Default**: false

 


## Using the vscpl2drv-websrv driver

