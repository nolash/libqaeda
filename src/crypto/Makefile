INCLUDES := -I.. -I../aux/include
CFLAGS +=  $(INCLUDES) -Wall

dummy:
	$(CC) $(CFLAGS) -c dummy.c 

gpg:
	$(CC) $(CFLAGS) -DLQ_GPG -c gcrypt.c

clean:
	rm -vf *.o

.PHONY: clean
