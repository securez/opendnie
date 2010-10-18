# Process this file with automake to create Makefile.in

includedir = @includedir@/opensc

MAINTAINERCLEANFILES = Makefile.in

#INCLUDES = $(CPPFLAGS) $(PCSC_CFLAGS) $(OPENSC_CFLAGS) -I$(top_srcdir)/src

AM_CFLAGS = $(OPTIONAL_OPENSSL_CFLAGS) $(LTLIB_CFLAGS)
INCLUDES = -I$(top_srcdir)/src



c_sources = \
        util.c \
        map.c \
        map_helper.c \
        pkcs15_default.c \
        pkcs15_standard.c \
        base_card.c \
        virtual_fs.c \
        virtual_pkcs15_fs.c \
        card_sync.c \
        card_helper.c \
        file_compression.c \
	trusted_channel_card.c

h_sources = \
        card_structures.h \
        util.h \
        map.h \
        map_helper.h \
        base_card.h \
        pkcs15_default.h \
        pkcs15_standard.h \
        virtual_fs.h \
        virtual_pkcs15_fs.h \
        card_sync.h \
        card_helper.h \
        file_compression.h 

noinst_LTLIBRARIES = libdniecard.la

libdniecard_la_SOURCES = \
        $(h_sources) \
        $(c_sources)

#libdniecard_la_LIBADD = $(PCSC_LIBS) $(OPENSC_LIBS) $(LTLIBLTDL)
