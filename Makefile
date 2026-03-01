CC?=     cc
CFLAGS+= -Wall -fsanitize=address -fstack-protector -g
LIBS+=   -lpthread -lssl -lcrypto
TARGET=  test-neverbleed
OBJS=    test.o neverbleed.o

all:    $(TARGET)

.c.o:
	$(CC) $(CFLAGS) -c $<

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBS) $(LDFLAGS)

test-handshake: $(TARGET)
	t/test_handshake.sh

clean:
	rm -fr $(OBJS) $(TARGET)

.PHONY: clean test-handshake
