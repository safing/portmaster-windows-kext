echo Release build of the Kernel Extenion and the glue dll
msbuild /t:Build /p:Configuration=Release /p:Platform=x64 portmaster-windows-kext.sln