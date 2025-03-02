OBJS := $(patsubst %.c,%.o,$(filter-out test.c,$(wildcard *.c)))
SOBJS := $(patsubst %.c,%.so.o,$(filter-out test.c,$(wildcard *.c)))
INCLUDES := -I.
CFLAGS += $(INCLUDES) -DRERR -DRERR_N_PFX=2
VERSION = 0.0.1

all: $(OBJS)

test: all
	$(CC) $(CFLAGS) test.c rerr.o -o test.out $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@ $(LDFLAGS)

clean:
	rm -vf *.o
	rm -vf *.out

archive:
	git archive --format=tar.gz HEAD -o rerr-$(VERSION).tar.gz

%.so.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@ -fpic

shared: $(SOBJS)


