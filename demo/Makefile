CC=gcc
CFLAGS=-static -Wall -g 
LDFLAGS=-L../src -ldp

ifneq ($(OS),Windows_NT)
	OS = $(shell uname -s)
endif

ifneq ($(OS),Darwin)
	LDFLAGS += -lpthread -lcrypto
endif

TARGET=demo

all: $(TARGET)

$(TARGET): demo.o
	$(CC) demo.o -o $@ $(LDFLAGS)

demo.o: demo.c
	$(CC) $(LDFLAGS) -c $< $(CFLAGS)

.PHONY: clean
clean:
	rm -rf *.o $(TARGET)
