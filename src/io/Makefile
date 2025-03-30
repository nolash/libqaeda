INCLUDES := -I.. -I../aux/include
CFLAGS +=  $(INCLUDES) -Wall

std:
	$(CC) $(CFLAGS) -g3 -c std.c 
	$(CC) $(CFLAGS) -g3 -c dummy.c 

clean:
	rm -vf *.o

.PHONY: clean
