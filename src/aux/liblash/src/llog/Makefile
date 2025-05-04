OBJS := $(patsubst %.c,%.o,$(filter-out test.c,$(wildcard *.c)))
SOBJS := $(patsubst %.c,%.so.o,$(filter-out test.c,$(wildcard *.c)))
INCLUDES := -I.
CFLAGS += $(INCLUDES)
VERSION = 0.0.1

all: $(OBJS)

hex:
	make -C ../hex all

test: hex all
	$(CC) $(CFLAGS) test.c llog.o ../hex/hex.o -o test.out $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -I../hex  -c $< -o $@ $(LDFLAGS)

clean:
	rm -vf *.o
	rm -vf *.out
	rm -vf *.tar.gz

archive:
	git archive --format=tar.gz HEAD -o llog-$(VERSION).tar.gz

%.so.o: %.c
	$(CC) $(CFLAGS) -I../hex -c $< -o $@ -fpic

shared: $(SOBJS)
