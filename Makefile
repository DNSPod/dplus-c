CC=gcc
CFLAGS=-static -Wall -g -O2
LDFLAGS=-lpthread

SOURCES=$(wildcard *.c)
OBJECTS=$(patsubst %.c, %.o, $(SOURCES))

TARGET=libdplubs.a

all: $(TARGET) $(OBJECTS)

$(TARGET): CFLAGS += -fPIC
$(TARGET): $(OBJECTS)
	ar rcs $@ $(OBJECTS)

%.o: %.c
	$(CC) $(LDFLAGS) -c $< $(CFLAGS)

.PHONY: clean
clean:
	rm -rf *.o $(TARGET)
