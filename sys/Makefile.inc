!IF "$(_BUILDARCH)" == "x86"
CPU=i386
!ELSE
CPU=$(_BUILDARCH)
!ENDIF

$(TARGETPATH)\$(CPU)\PortmasterKext64.inf: PortmasterKext64.inf
	copy /y PortmasterKext64.inf $@
$(TARGETPATH)\$(CPU)\WdfCoInstaller01009.dll:
	copy /y $(BASEDIR)\redist\wdf\$(_BUILDARCH)\WdfCoInstaller01009.dll $@
