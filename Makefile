CC?=    cc
CFLAGS+=    -Wall -fsanitize=address -fstack-protector -g
TARGET= neverbleed
OBJS=   test.o neverbleed.o
PREFIX?=    /usr/local

LIBS=   -lpthread -lssl -lcrypto

all:    $(TARGET)

.c.o:
	$(CC) $(CFLAGS) -c $<

neverbleed:	$(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBS)

clean:
	rm -fr *.o $(TARGET)
