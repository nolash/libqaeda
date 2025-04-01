OBJS := $(patsubst %.c,%.o,$(wildcard *.c))
CFLAGS += -Wall -Werror

all:
	make -C endian all
	make -C hex all
	make -C llog all
	make -C rerr all
	make -C case all

clean:
	make -C endian clean
	make -C hex clean
	make -C llog clean
	make -C rerr clean
	make -C case clean

test: all
	make -C endian test
	make -C hex test
	make -C llog test
	make -C rerr test
	make -C case test

lib: all
	$(AR) rcs liblash.a ./endian/*.o ./hex/*.o ./llog/*.o ./rerr/*.o ./case/*.o

shared:
	make -C endian shared
	make -C hex shared
	make -C llog shared
	make -C rerr shared
	make -C case shared
	$(CC) $(CFLAGS) -shared -o liblash.so endian/strip.so.o endian/endian.so.o hex/hex.so.o llog/llog.so.o rerr/rerr.so.o case/case.so.o

install: lib shared
	cat -v endian/*.h > $(DESTDIR)/include/lash.h
	install -m0644 -v endian/*.h -t $(DESTDIR)/include
	cat -v hex/*.h >> $(DESTDIR)/include/lash.h
	install -m0644 -v hex/*.h -t $(DESTDIR)/include
	cat -v llog/*.h >> $(DESTDIR)/include/lash.h
	install -m0644 -v llog/*.h -t $(DESTDIR)/include
	cat -v rerr/*.h >> $(DESTDIR)/include/lash.h
	install -m0644 -v rerr/*.h -t $(DESTDIR)/include
	cat -v case/*.h >> $(DESTDIR)/include/lash.h
	install -m0644 -v case/*.h -t $(DESTDIR)/include
	#cp -v liblash.so $(DESTDIR)/lib/
	install -m0644 -v liblash.so -t $(DESTDIR)/lib
	cd $(DESTDIR)/lib && ln -svf liblash.so liblash.so.$(VERSION)
	install -m0644 -v liblash.a -t $(DESTDIR)/lib


.PHONY: clean
