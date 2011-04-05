all: pinentry_test pinentry_test2 hex2bin hexdump pubkey2ssh

PINENTRY = /usr/bin/pinentry

INCLUDES = -I/usr/include/libassuan2
LIBS = -lassuan -lgpg-error

TARGETS = pinentry_test pinentry_test2 hex2bin hexdump pubkey2ssh

SRCS = pinentry_test.c pinentry_test2.c hex2bin.c hexdump.c pubkey2ssh.c
OBJS = pinentry_test.o pinentry_test2.o hex2bin.o hexdump.o pubkey2ssh.o

CC = gcc
CFLAGS = -g -Wall -DPIN_ENTRY=\"$(PINENTRY)\"

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $<  -o $@

pubkey2ssh: pubkey2ssh.o
	$(CC) $(CFLAGS) $< -o $@  -lssl -lcrypto

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
