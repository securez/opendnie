TOPDIR = ..\..

TARGET = opensc-minidriver.dll
OBJECTS = minidriver.obj

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

all: $(TARGET)

$(TARGET): $(OBJECTS)
	echo LIBRARY $* > $*.def
	echo EXPORTS >> $*.def
	type minidriver.exports >> $*.def
	link /dll $(LINKFLAGS) /def:$*.def /out:$(TARGET) $(OBJECTS) ..\libopensc\opensc.lib $(ZLIB_LIB) $(OPENSSL_LIB) ..\common\libscdl.lib ws2_32.lib gdi32.lib advapi32.lib Crypt32.lib User32.lib
	if EXIST $(TARGET).manifest mt -manifest $(TARGET).manifest -outputresource:$(TARGET);2
