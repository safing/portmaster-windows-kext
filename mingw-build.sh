#!/bin/bash

# Script for MinGW/Linux cross compilation.
# NOTE: run wddk-build.bat before this script.

set -e

#JCS:
#	- Only build 64Bit Version, since 32Bit cannot be built on Win10 with WDDK 7.1
#	- Removed option "-nostdlib" from the line "dll/pm_kernel.o dll/pm_kernel.def $CLIBS"
#	  to allow direct Debugging from dll to stderr.

ENV="x86_64-w64-mingw32"
CPU=amd64
BITS=64
MANGLE=
HAVE_SYS=yes

if [ ! -d install/WDDK/$CPU ]
then
	echo "WARNING: missing WDDK build; run wddk-build.bat first"
	HAVE_SYS=no
fi
echo "BUILD MINGW-$CPU"
CC="$ENV-gcc"
COPTS="-fno-ident -shared -Wall -Wno-pointer-to-int-cast -Os -Iinclude/
	-Wl,--enable-stdcall-fixup -Wl,--entry=${MANGLE}portmasterDllEntry"
CLIBS="-lgcc -lkernel32 -ladvapi32"
STRIP="$ENV-strip"
DLLTOOL="$ENV-dlltool"
if [ -x "`which $CC`" ]
then
	echo "\tmake install/MINGW/$CPU..."
	mkdir -p "install/MINGW/$CPU"
	echo "\tbuild install/MINGW/$CPU/portmaster.dll ..."
	$CC $COPTS -c dll/pm_kernel_glue.c -o dll/pm_kernel_glue.o
	$CC $COPTS -c dll/pm_debug.c -o dll/pm_debug.o
	$CC $COPTS -c dll/pm_api.c -o dll/pm_api.o
	$CC $COPTS -o "install/MINGW/$CPU/pm_kernel_glue.dll" \
		dll/pm_kernel_glue.o \
		dll/pm_debug.o \
		dll/pm_api.o \
		dll/pm_api.def \
		$CLIBS
	$STRIP "install/MINGW/$CPU/pm_kernel_glue.dll"
	echo "\tbuild install/MINGW/$CPU/pm_kernel_glue.lib..."
	$DLLTOOL --dllname install/MINGW/$CPU/pm_kernel_glue.dll \
		--def dll/pm_api.def \
		--output-lib install/MINGW/$CPU/pm_kernel_glue.lib

	echo "\tbuild install/MINGW/$CPU/portmaster_test.exe..."
	$CC -s -O2 -Iinclude/ examples/portmaster/portmaster_test.c \
		-o "install/MINGW/$CPU/portmaster_test.exe" -lpm_kernel_glue \
		-lpsapi -lshlwapi -L"install/MINGW/$CPU/"


	if [ $HAVE_SYS = yes ]
	then
		echo "\tcopy install/MINGW/$CPU/pm_kernel$BITS.sys..."
		cp install/WDDK/$CPU/pm_kernel$BITS.sys install/MINGW/$CPU
	fi
else
	echo "WARNING: $CC not found"
fi
