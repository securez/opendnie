all: pinentry_test

PINENTRY = /usr/bin/pinentry

INCLUDES = -I/usr/include/libassuan2
LIBS = -lassuan

SRCS = pinentry_test.c
OBJS = pinentry_test.o

CC = gcc
CFLAGS = -g -Wall -DPIN_ENTRY=\"$(PINENTRY)\"

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $<  -o $@

pinentry_test: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o pinentry_test $(LIBS)

clean: 
	rm -f $(OBJS) pinentry_test 
