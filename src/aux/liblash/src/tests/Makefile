TESTS := $(patsubst %.c,%.testbin,$(wildcard *.c))
LINKOBJS := $(wildcard ../*.o)
CFLAGS += -I.. -Wall

all: $(TESTS)

%.testbin: %.c
	$(CC) $(CFLAGS) $< -o $@ $(LINKOBJS)
	./$@

#test_run: $(wildcard out_*)
#	for f in $^; do ./$$f; done

test: all

clean:
	rm -vf *.testbin

.PHONY: clean
