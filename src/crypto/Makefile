INCLUDES := -I.. -I../aux/include
CFLAGS += $(INCLUDES) -Wall -fPIC

dummy:
	$(CC) $(CFLAGS) -c dummy.c 

gpg:
	$(CC) $(CFLAGS) -DLQ_GPG -c gcrypt.c

gpg-shared:
	$(CC) $(CFLAGS) -DLQ_GPG -fPIC -c gcrypt.c -o gcrypt.so.o

clean:
	rm -vf *.o

.PHONY: clean
