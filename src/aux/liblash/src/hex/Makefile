OBJS := $(patsubst %.c,%.o,$(filter-out test.c,$(wildcard *.c)))
SOBJS := $(patsubst %.c,%.so.o,$(filter-out test.c,$(wildcard *.c)))
INCLUDES := -I.
CFLAGS += $(INCLUDES)
VERSION = 0.0.1
CFLAGS += -Wall -Werror

all: $(OBJS)

test: all
	$(CC) $(CFLAGS) test.c hex.o -o test.out $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@ $(LDFLAGS)

clean:
	rm -vf *.o
	rm -vf *.out
	rm -vf *.tar.gz

archive:
	git archive --format=tar.gz HEAD -o hex-$(VERSION).tar.gz

%.so.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@ -fpic

shared: $(SOBJS)


