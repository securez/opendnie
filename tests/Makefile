all: pinentry_test

INCLUDES = -I/usr/include/libassuan2
LIBS = -lassuan

SRCS = pinentry_test.c
OBJS = pinentry_test.o

CC = gcc
CFLAGS = -g -Wall

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $<  -o $@

pinentry_test: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o pinentry_test $(LIBS)

clean: 
	rm -f $(OBJS) pinentry_test 
