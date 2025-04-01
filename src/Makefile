INCLUDES := -I. -I./aux/include
CFLAGS +=  $(INCLUDES) -Wall -DRERR
LIBOBJFILES = ./asn1/*.o ./*.o ./lq/*.o ./store/file.o ./mem/std.o ./io/std.o ./crypto/gcrypt.o
LIBOBJEMBED = ./aux/lib/liblash.a #./aux/lib/libcwalk.a
LIBS := `pkg-config --libs libtasn1 libgcrypt` -L./aux/lib -llash -lcwalk

all: all-gpg
all-dummy: asn1 aux core dummy
all-gpg: asn1 aux core gpg

dev-lib: all
	#ar rcs liblq.a lq/config.o crypto/gcrypt.o store/file.o mem/std.o io/std.o debug.o aux/lib/libhashmap.a 
	ar rcs liblq.a $(LIBOBJFILES)
	libtool --mode=link --tag=CC $(CC) -static -o libqaeda.a liblq.a ./aux/lib/liblash.a ./aux/lib/libcwalk.a

test-lib:
	ar rcs libqaedatest.a $(LIBOBJFILES) aux/lib/libhashmap.a 

core: dummy
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

test: all test-lib 
	make -C test

clean:
	make -C asn1 clean
	make -C lq clean
	make -C test clean
	make -C mem clean
	make -C crypto clean
	rm -vf *.o *.a *.so

#shared-gpg: core aux asn1 gpg
	#make -C aux/liblash/src lib
	#$(CC) $(CFLAGS) -shared -o libqaeda.so $(LIBOBJFILES) $(LIBOBJEMBED)
			

.PHONY: clean asn1 aux
