#See the file LICENSE for the license

CC=gcc
CFLAGS=-static -Wall -g 
LDFLAGS=

ifneq ($(OS),Windows_NT)
	OS = $(shell uname -s)
endif

ifneq ($(OS),Darwin)
	LDFLAGS += -lpthread -lcrypto
endif

SOURCES=$(wildcard *.c)
OBJECTS=$(patsubst %.c, %.o, $(SOURCES))

TARGET=libdp.a

all: $(TARGET)

$(TARGET): CFLAGS += -fPIC
$(TARGET): $(OBJECTS)
	ar rcs $@ $(OBJECTS)

%.o: %.c
	$(CC) $(LDFLAGS) -c $< $(CFLAGS)

.PHONY: clean
clean:
	rm -rf *.o $(TARGET)
