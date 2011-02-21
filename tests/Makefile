all: pinentry_test pinentry_test2 hex2bin hexdump

PINENTRY = /usr/bin/pinentry

INCLUDES = -I/usr/include/libassuan2
LIBS = -lassuan -lgpg-error

TARGETS = pinentry_test pinentry_test2 hex2bin hexdump
SRCS = pinentry_test.c pinentry_test2.c hex2bin.c hexdump.c
OBJS = pinentry_test.o pinentry_test2.o hex2bin.o hexdump.o

CC = gcc
CFLAGS = -g -Wall -DPIN_ENTRY=\"$(PINENTRY)\"

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $<  -o $@

pinentry_test2: pinentry_test2.o
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

pinentry_test: pinentry_test.o
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

hex2bin: hex2bin.o
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

hexdump: hexdump.o
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

clean: 
	rm -f $(OBJS) $(TARGETS)
