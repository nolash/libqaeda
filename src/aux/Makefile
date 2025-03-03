DESTDIR := `realpath .`
export DESTDIR

install: hashmap
	make DESTDIR=`realpath .` -C liblash install
	install -m0644 -v hashmap.c/*.h -t $(DESTDIR)/include

hashmap:
	$(CC) $(CFLAGS) -c hashmap.c/hashmap.c -o hashmap.c/hashmap.o
	$(AR) rcs $(DESTDIR)/lib/libhashmap.a hashmap.c/hashmap.o
