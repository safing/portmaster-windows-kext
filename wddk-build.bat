:: Script for WDDK compilation.
:: NOTE: Use this script to build the driver

@echo on

set WDDK_INSTALL=install\WDDK\
mkdir %WDDK_INSTALL%

build -cZgew
