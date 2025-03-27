INCLUDES := -I. -I./aux/include
CFLAGS +=  $(INCLUDES) -Wall

all: all-gpg
all-dummy: asn1 aux core dummy
all-gpg: asn1 aux core gpg
lib: all

lib:
	ar rcs liblq.a lq/config.o crypto/gcrypt.o store/file.o mem/std.o io/std.o debug.o aux/lib/libhashmap.a 

core:
	$(CC) $(CFLAGS) -c debug.c
	make -C lq

aux:
	make -C aux

asn1:
	make -C asn1 all

gpg:
	make -C crypto gpg
	make -C mem std
	make -C io std
	make -C store dummy

dummy:
	make -C crypto dummy
	make -C mem std
	make -C io std
	make -C store dummy

test: all
	make -C test

clean:
	make -C asn1 clean
	make -C lq clean
	make -C test clean
	make -C mem clean
	make -C crypto clean

.PHONY: clean asn1 aux
