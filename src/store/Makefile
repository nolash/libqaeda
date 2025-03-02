INCLUDES := -I.. -I../aux/include
CFLAGS +=  $(INCLUDES) -Wall

all:
	$(CC) $(CFLAGS) -c file.c 

dummy: all
	$(CC) $(CFLAGS) -c dummy.c 

clean:
	rm -vf *.o

.PHONY: clean
