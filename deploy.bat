echo Compile, Sign and Copy the Kernel Driver with the dll
set WDDK_SOURCE=install\WDDK\x64\Debug\pm_kernel64.sys
del WDDK_SOURCE

set DLL_SOURCE=install\DLL\x64\Debug\pm_kernel_glue.dll
del DLL_SOURCE

msbuild /t:Clean /p:Configuration=Debug /p:Platform=x64
msbuild /t:Build /p:Configuration=Debug /p:Platform=x64
SignTool sign /v /s TestCertStoreName /n TestCertName /fd SHA256 %WDDK_SOURCE%

echo Copy the Kernel Driver to Portmaster updates dir as dev version
copy %WDDK_SOURCE% C:\ProgramData\Safing\Portmaster\updates\windows_amd64\kext\portmaster-kext_v0-0-0.sys
copy %DLL_SOURCE% C:\ProgramData\Safing\Portmaster\updates\windows_amd64\kext\portmaster-kext_v0-0-0.dll