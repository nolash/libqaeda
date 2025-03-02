OBJS := $(patsubst %.c,%.o,$(wildcard *.c))
SOBJS := $(patsubst %.c,%.so.o,$(wildcard *.c))
CFLAGS += -Wall -Werror
VERSION = 0.0.1


all: $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -vf *.o

%.so.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@ -fpic

shared: $(SOBJS)

test: all

.PHONY: clean

