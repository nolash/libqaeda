INCLUDES := -I.. -I../aux/include
CFLAGS +=  $(INCLUDES) -Wall
LDFLAGS += -L../aux/lib -lhashmap

all:
	$(CC) $(CFLAGS) -c file.c 
	$(CC) $(CFLAGS) -c mem.c 

dummy: all
	$(CC) $(CFLAGS) -c dummy.c 

clean:
	rm -vf *.o

.PHONY: clean
