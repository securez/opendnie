# Process this file with automake to create Makefile.in

includedir = @includedir@/opensc

MAINTAINERCLEANFILES = Makefile.in

EXTRA_DIST = libopensc-dnie.pc.in

INCLUDES = $(CPPFLAGS) $(PCSC_CFLAGS) $(OPENSC_CFLAGS) $(ASSUAN_CFLAGS) -I$(top_srcdir)/src/common
AM_LDFLAGS =

c_sources = \
        $(top_srcdir)/src/common/util.c \
        $(top_srcdir)/src/common/map.c \
        $(top_srcdir)/src/common/map_helper.c \
        \
        pkcs15_default.c \
        \
        pkcs15_standard.c \
        \
        base_card.c \
	\
	dialog.c \
        \
        virtual_fs.c \
        virtual_pkcs15_fs.c \
        card_sync.c \
        card_helper.c \
        file_compression.c \
	trusted_channel_card.c

h_sources = \
        $(top_srcdir)/src/common/card_structures.h \
        $(top_srcdir)/src/common/util.h \
        $(top_srcdir)/src/common/map.h \
        $(top_srcdir)/src/common/map_helper.h \
	$(top_srcdir)/src/common/i18n.h \
        base_card.h \
        pkcs15_default.h \
        pkcs15_standard.h \
        virtual_fs.h \
        virtual_pkcs15_fs.h \
        card_sync.h \
        card_helper.h \
        file_compression.h 

lib_LTLIBRARIES = libopensc-dnie.la
libopensc_dnie_la_SOURCES = \
        $(h_sources) \
        $(c_sources)


libopensc_dnie_la_LDFLAGS = -version-info @OPENSC_DNIE_LT_CURRENT@:@OPENSC_DNIE_LT_REVISION@:@OPENSC_DNIE_LT_AGE@
libopensc_dnie_la_LIBADD = $(PCSC_LIBS) $(OPENSC_LIBS) $(LTLIBLTDL) $(ASSUAN_LIBS)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libopensc-dnie.pc
