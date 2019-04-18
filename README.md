# Portmaster Windows Kernel Extensions

This Windows kernel-mode driver provides the Portmaster with a high performance OS integration.
It provides an internal caching for best performance and lets the Portmaster do all the decision making.

### Architecture

The basic architecture is as follows:

                              +----------------+
                              |                |
                      +------>|   Portmaster   |------>+
                      |       |                |       |
                      |       +----------------+       |
                      |                                |
                      | (2a) verdict request           | (3) set verdict
    [user mode]       |                                |
    ..................|................................|........................
    [kernel mode]     |                                |
                      |                                |
                 +-------------------------------------|---+
                 |                                     +-> | (2b/4) handle packet
     (1) packet  |   Driver                    if in cache | according to verdict
    ------------>|   (2) check verdict cache   +---------> |-------------------->
                 |                                         |
                 +-----------------------------------------+

This architecture allows for high performance, as most packages are handled directly in kernel space. Only new connections need to be pushed into userland so that the Portmaster can set a verdict for them.

The Driver is installed into the Windows network stack - between OSI layer 2 and 3 - and sees IP and everything above.

This is how packets are handled:

1.  Windows Kernel processes a packet in the TCP/IP stack (netbuffer).
2.  Windows Kernel presents packet to Portmaster Kernel Extension via a callout.
3.  The Portmaster Kernel Extension check its cache for a verdict for the given packet, using network (IP) and transport (TCP/UDP/...) layer data.
4.  If not found, the Portmaster Kernel Extension presents the packet to the Portmaster via the blocking API call `PortmasterRecvVerdictRequest`.
5.  The Portmaster inspects the packet information (`packetInfo`) and sets verdict via `PortmasterSetVerdict`.
6.  If necessary, the Portmaster may also inspect the payload of packet via `PortmasterGetPayload`, using the packet ID previously received by `PortmasterRecvVerdictRequest`.
7.  The Portmaster Kernel Extension holds intercepted packet in a packet cache until the verdict is set.
8.  If the packet cache is full, the oldest packet will be dropped, so that the newest packet can be stored.

### Building

The Windows Portmaster Kernel Extension is currently only developed and tested for the amd64 (64-bit) architecture.

Prerequesites:

- Driver (`.sys`)
  - [WDK 7.1](https://www.microsoft.com/en-us/download/details.aspx?id=11800)
- Library (`.dll`)
  - MINGW (x64)

Build driver:

    :: open a _x86 Free Build Environment_ console
    wddk-build.bat
    :: built driver lands in install\WDDK\amd64

    :: shortcut to build, sign and copy the driver to install\MINGW\amd64:
    deploy.bat

Build library:

    # open a mingw x64 console
    ./mingw-build.sh
    # built library lands in install\MINGW\amd64

Test Signing:  
In order to test the driver on your machine, you will have to test sign it (starting with Windows 10). Here is how you can do this:

    :: Open a *x64 Free Build Environment* console as Administrator.

    :: Run the MakeCert.exe tool to create a test certificate:
    MakeCert -r -pe -ss TestCertStoreName -n "CN=TestCertName" CertFileName.cer

    :: Install the test certificate with CertMgr.exe:
    CertMgr /add CertFileName.cer /s /r localMachine root

    :: Sign pm_kernel64.sys with the test certificate:
    SignTool sign /v /s TestCertStoreName /n TestCertName pm_kernel64.sys

    :: Before you can load test-signed drivers, you must enable Windows test mode. To do this, run this command:
    Bcdedit.exe -set TESTSIGNING ON
    :: Then, restart Windows. For more information, see The TESTSIGNING Boot Configuration Option.

### Releasing

Please check the `release` directory for further information on releasing the Portmaster Kernel Extension.

### About

The Portmaster Windows Kernel Extension is based on / influenced by the excellent work of:
- [WinDivert](https://github.com/basil00/Divert), by basil.
- [WFPStarterKit](https://github.com/JaredWright/WFPStarterKit), by Jared Wright
