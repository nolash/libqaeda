DESTDIR := `realpath .`
export DESTDIR
CFLAGS += -Iinclude

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


shared:
	gcc $(CFLAGS) -fPIC -c cwalk/src/cwalk.c -o cwalk.o
	gcc $(CFLAGS) -fPIC -c hashmap.c/hashmap.c -o hashmap.o
	gcc $(CFLAGS) -fPIC -c liblash/src/case/case.c -o case.o
	gcc $(CFLAGS) -fPIC -c liblash/src/hex/hex.c -o hex.o
	gcc $(CFLAGS) -fPIC -c liblash/src/endian/endian.c -o endian.o
	gcc $(CFLAGS) -fPIC -c liblash/src/llog/llog.c -o llog.o
	gcc $(CFLAGS) -fPIC -c liblash/src/rerr/rerr.c -o rerr.o
