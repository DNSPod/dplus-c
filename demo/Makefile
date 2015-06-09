CC=gcc
CFLAGS=-static -Wall -g 
LDFLAGS=-L../src -ldp -lpthread  -lcrypto

TARGET=demo

all: $(TARGET)

$(TARGET): demo.o
	$(CC) demo.o -o $@ $(LDFLAGS)

demo.o: demo.c
	$(CC) $(LDFLAGS) -c $< $(CFLAGS)

.PHONY: clean
clean:
	rm -rf *.o $(TARGET)
