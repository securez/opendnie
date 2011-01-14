all: pinentry_test hex2bin

PINENTRY = /usr/bin/pinentry

INCLUDES = -I/usr/include/libassuan2
LIBS = -lassuan

TARGETS = pinentry_test hex2bin
SRCS = pinentry_test.c hex2bin.c
OBJS = pinentry_test.o hex2bin.o

CC = gcc
CFLAGS = -g -Wall -DPIN_ENTRY=\"$(PINENTRY)\"

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $<  -o $@

pinentry_test: pinentry_test.o
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

hex2bin: hex2bin.o
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

clean: 
	rm -f $(OBJS) $(TARGETS)
