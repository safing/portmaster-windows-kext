@echo off
set DISTDIR=dist\windows_amd64\kext
set SIGNEDDIR=Signed\drivers\PortmasterKext

echo.
echo =====
echo copying files ...
mkdir %DISTDIR%
echo copy %SIGNEDDIR%\PortmasterKext64.sys %DISTDIR%\portmaster-kext_vX-X-X.sys
copy %SIGNEDDIR%\PortmasterKext64.sys %DISTDIR%\portmaster-kext_vX-X-X.sys
echo copy %SIGNEDDIR%\PortmasterKext64.dll %DISTDIR%\portmaster-kext_vX-X-X.dll
copy %SIGNEDDIR%\PortmasterKext64.dll %DISTDIR%\portmaster-kext_vX-X-X.dll

echo.
echo =====
echo OPTIONAL:
echo YOUR TURN: sign .sys and .dll (add your sig for additional transparency)
echo use something along the lines of:
echo.
echo signtool sign /tr http://timestamp.digicert.com /td sha256 /fd sha256 /a /as %DISTDIR%\portmaster-kext_vX-X-X.sys
echo signtool sign /tr http://timestamp.digicert.com /td sha256 /fd sha256 /a /as %DISTDIR%\portmaster-kext_vX-X-X.dll
echo.

echo.
echo =====
echo YOUR TURN: rename %DISTDIR%\portmaster-kext-vX-X-X.sys and %DISTDIR%\portmaster-kext-vX-X-X.dll to correct versions!
echo DONE!
echo.
