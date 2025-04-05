OBJS := $(patsubst %.c,%.o,$(filter-out main.c,$(wildcard *.c)))
INCLUDES := -I.. -I../aux/include
CFLAGS +=  $(INCLUDES) -Wall
LIBS := ../asn1/defs_asn1_tab.o `pkg-config --libs libtasn1` -L../aux/lib -llash

LDFLAGS += $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@ $(LDFLAGS)

all: $(OBJS)

clean:
	rm -vf *.o

.PHONY: clean
