OBJS := $(patsubst %.c,%.o,$(filter-out main.c,$(wildcard *.c)))
INCLUDES := -I..
CFLAGS +=  $(INCLUDES) -Wall

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@ $(LDFLAGS)

all: $(OBJS)
