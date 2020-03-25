CC=gcc
CFLAGS=
LDFLAGS=-lcrypto -lm
SOURCES=bar.c
EXECUTABLE=bar
all:
	$(CC) $(CFLAGS) $(SOURCES) $(LDFLAGS) -o $(EXECUTABLE)
clean:
	rm -rf $(EXECUTABLE)