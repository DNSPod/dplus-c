CC=gcc
CFLAGS=-static -Wall -g 
LDFLAGS=-L../src -ldp

ifneq ($(OS),Windows_NT)
	OS = $(shell uname -s)
endif

ifneq ($(OS),Darwin)
	LDFLAGS += -lpthread -lcrypto
endif

SOURCES=$(wildcard *.c)
OBJECTS=$(patsubst %.c, %.o, $(SOURCES))

TARGET=test

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(LDFLAGS) -c $< $(CFLAGS)

.PHONY: clean
clean:
	rm -rf *.o $(TARGET)
