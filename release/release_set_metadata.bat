@echo off
set CABDIR=PortmasterKext

set VERSION="1.0.8.0 (%date%)"
set FILEDESCR_SYS=/s desc "Portmaster Windows Kernel Extension Driver"
set FILEDESCR_DLL=/s desc "Portmaster Windows Kernel Extension DLL"
set COMPINFO=/s company "Safing ICS Technologies GmbH" /s (c) "Safing ICS Technologies GmbH"
set PRODINFO=/s product "Portmaster Windows Kernel Extension" /pv "1.0.8.0"

verpatch /va %CABDIR%\amd64\PortmasterKext64.sys %VERSION% %FILEDESCR_SYS% %COMPINFO% %PRODINFO% %BUILDINFO%
verpatch /va %CABDIR%\amd64\PortmasterKext64.dll %VERSION% %FILEDESCR_DLL% %COMPINFO% %PRODINFO% %BUILDINFO%
