@echo off
set CABDIR=PortmasterKext
set INSTALL_WDDK_AMD64=..\install\WDDK\x64\Release
set INSTALL_DLL_AMD64=..\install\DLL\x64\Release

echo.
echo =====
echo checking if build is set to release ...
findstr /R /C:"^#define DEBUG_ON" ..\include\pm_debug.h
if %ERRORLEVEL% equ 0 echo BUILD IS SET TO DEBUG! && exit /b

echo.
echo =====
echo removing old files ...
rmdir /Q /S %CABDIR%
del PortmasterKext.cab

echo.
echo =====
echo copying files ...
mkdir %CABDIR%\amd64
copy %INSTALL_WDDK_AMD64%\pm_kernel64.sys %CABDIR%\amd64\PortmasterKext64.sys
copy %INSTALL_WDDK_AMD64%\pm_kernel64.pdb %CABDIR%\amd64\PortmasterKext64.pdb
copy %INSTALL_DLL_AMD64%\pm_kernel_glue.dll %CABDIR%\amd64\PortmasterKext64.dll
copy %INSTALL_WDDK_AMD64%\PortmasterKext64.inf %CABDIR%\amd64\PortmasterKext64.inf

echo.
echo =====
echo removing existing signatures ...
signtool remove /s %CABDIR%\amd64\PortmasterKext64.sys
:: signtool remove /s %CABDIR%\amd64\PortmasterKext64.pdb
:: signtool remove /s %CABDIR%\amd64\PortmasterKext64.dll

echo.
echo =====
echo creating .cab ...
MakeCab /f PortmasterKext.ddf

echo.
echo =====
echo cleaning up ...
del setup.inf
del setup.rpt
move disk1\PortmasterKext.cab PortmasterKext.cab
rmdir disk1

echo.
echo =====
echo YOUR TURN: sign the .cab
echo use something along the lines of:
echo.
echo signtool sign /tr http://timestamp.digicert.com /td sha256 /fd sha256 /a PortmasterKext.cab
echo.
