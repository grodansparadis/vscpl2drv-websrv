% vscpl2drv-websrv(1) VSCP Level II Web Server Driver
% Åke Hedmann, Grodans Paradis AB
% June 30, 2021

# NAME

vscpl2drv-websrv - VSCP Level II web server Driver

# SYNOPSIS

vscpl2drv-template

# DESCRIPTION

This driver interface SocketCAN, the official CAN API of the Linux kernel, has been included in the kernel for a long time now. Meanwhile, the official Linux repository has device drivers for all major CAN chipsets used in various architectures and bus types. SocketCAN offers the user a multiuser capable as well as hardware independent socket-based API for CAN based communication and configuration. Socketcan nowadays give access to the major CAN adapters that is available on the market. Note that as CAN only can handle Level I events only events up to class < 1024 can be sent to this device. Other events will be filtered out.

## Configuration

The *configuration string* is the first configuration data that is read by the driver. The driver will, after it is read and parsed, ask the server for driver specific configuration data. This data is fetched with the same pattern for all drivers. Variables are formed by the driver name + some driver specific remote variable name. If this variable exist and contains data it will be used as configuration for the driver regardless of the content of the configuration string.

### Adding the driver to the VSCP daemon.



# SEE ALSO

`vscpd` (8).
`uvscpd` (8).
`vscpworks` (1).
`vscpcmd` (1).
`vscp-makepassword` (1).
`vscphelperlib` (1).

The VSCP project homepage is here <https://www.vscp.org>.

The [manual](https://grodansparadis.gitbooks.io/the-vscp-daemon) for vscpd contains full documentation. Other documentation can be found here <https://grodansparadis.gitbooks.io>.

The vscpd source code may be downloaded from <https://github.com/grodansparadis/vscp>. Source code for other system components of VSCP & Friends are here <https://github.com/grodansparadis>

# COPYRIGHT
Copyright 2000-2021 Åke Hedman, the VSCP Project - MIT license.




