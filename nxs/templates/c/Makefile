CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=c11
TARGET = nxs-c-template

.PHONY: all clean

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)
