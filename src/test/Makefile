OBJS := $(patsubst %.c,%.o,$(wildcard *.c))
INCLUDES := -I..
CFLAGS +=  $(INCLUDES) -Wall -g3

%.o: %.c
	$(CC) $(CFLAGS) $< -o $*_bin $(LDFLAGS) ../crypto/dummy.o ../mem/std.o -lcheck
	./$*_bin

all: $(OBJS)
