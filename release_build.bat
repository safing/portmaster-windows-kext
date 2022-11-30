echo Release build of the Kernel Extenion
msbuild /t:Clean /p:Configuration=Release /p:Platform=x64 portmaster-windows-kext.sln
msbuild /t:Build /p:Configuration=Release /p:Platform=x64 portmaster-windows-kext.sln