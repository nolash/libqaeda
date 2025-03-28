DESTDIR := `realpath .`
export DESTDIR

install: cwalk hashmap
	make DESTDIR=`realpath .` -C liblash install
	install -m0644 -v hashmap.c/*.h -t $(DESTDIR)/include

cwalk:
	make -C cwalk all
	install -vm0644 cwalk/build/usr/local/lib/*.so -t $(DESTDIR)/lib/
	install -vm0644 cwalk/build/usr/local/lib/*.a -t $(DESTDIR)/lib/
	install -vm0644 cwalk/build/usr/local/include/*.h -t $(DESTDIR)/include/

hashmap:
	install -m0755 -v -d $(DESTDIR)/lib
	$(CC) $(CFLAGS) -c hashmap.c/hashmap.c -o hashmap.c/hashmap.o
	$(AR) rcs $(DESTDIR)/lib/libhashmap.a hashmap.c/hashmap.o
