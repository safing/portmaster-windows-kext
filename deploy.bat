rem reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print" /V DEFAULT /t REG_DWORD /d 0xf
echo Compile, Sign and Copy the Kernel Driver (but not the dll!)
set WDDK_SOURCE=install\WDDK\amd64\pm_kernel64.sys
rem set MINGW_DEST=install\MINGW\amd64\pm_kernel64.sys
set MINGW_DEST=install\MINGW\amd64\
del WDDK_SOURCE
del MINGW_DEST
call wddk-build.bat
SignTool sign /v /s TestCertStoreName /n TestCertName %WDDK_SOURCE%
echo Copy the signed Kernel Driver from %WDDK_SOURCE% to %MINGW_DEST%
copy %WDDK_SOURCE% %MINGW_DEST%
