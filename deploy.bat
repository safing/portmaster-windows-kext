echo Compile, Sign and Copy the Kernel Driver
set WDDK_SOURCE=install\WDDK\x64\Debug\pm_kernel64.sys
del %WDDK_SOURCE%

msbuild /t:Clean /p:Configuration=Debug /p:Platform=x64 portmaster-windows-kext.sln
msbuild /t:Build /p:Configuration=Debug /p:Platform=x64 portmaster-windows-kext.sln

SignTool sign /v /s TestCertStoreName /n TestCertName /fd SHA256 %WDDK_SOURCE%

echo Copy the Kernel Driver to Portmaster updates dir as dev version
copy %WDDK_SOURCE% C:\ProgramData\Safing\Portmaster\updates\windows_amd64\kext\portmaster-kext_v0-0-0.sys
