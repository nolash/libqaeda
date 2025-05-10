OBJS := $(patsubst %.c,%.o,$(wildcard *.c))
INCLUDES := -I.. -I../aux/include `pkg-config --cflags libtasn1 libgcrypt`
CFLAGS += $(INCLUDES) -Wall -g3
#LIBS := ../asn1/defs_asn1_tab.o `pkg-config --libs libtasn1 libgcrypt` -L../aux/lib -llash -lhashmap
LIBS := ../asn1/defs_asn1_tab.o `pkg-config --libs libtasn1 libgcrypt` -L.. -L../aux/lib -lqaeda -lhashmap
#LDFLAGS := -lcheck -lsubunit -lm $(LIBS)
LDFLAGS := -lcheck $(LIBS)
COMMONOBJS = ../mem/std.o ../lq/config.o ../lq/err.o ../lq/base.o ../debug.o

all: build all-tests
#all: build one-test

all-tests:
	cK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_test_bin
	CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_debug_bin
	CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_config_bin
	CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_crypto_bin
	CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_msg_bin
	CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_cert_bin
	CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_envelope_bin
	CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_trust_bin
	CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_store_bin
	CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_query_bin

one-test: build
	CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_cert_bin
	#CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_query_bin

test: all

build:
	#$(CC) $(CFLAGS) test_test.c -o test_test_bin $(COMMONOBJS) ../io/dummy.o ../store/mem.o $(LDFLAGS) 
	#$(CC) $(CFLAGS) test_test.c -o test_test_bin $(COMMONOBJS) ../io/std.o ../store/file.o $(LDFLAGS) 
	$(CC) $(CFLAGS) test_test.c -o test_test_bin $(COMMONOBJS) $(LDFLAGS) 
	$(CC) $(CFLAGS) test_debug.c -o test_debug_bin $(COMMONOBJS) $(LDFLAGS)
	$(CC) $(CFLAGS) test_config.c -o test_config_bin $(COMMONOBJS) $(LDFLAGS)
	#$(CC) $(CFLAGS) test_crypto.c -o test_crypto_bin $(COMMONOBJS)  ../store/file.o ../io/std.o ../crypto/gcrypt.o $(LDFLAGS) -lgcrypt
	$(CC) $(CFLAGS) test_crypto.c -o test_crypto_bin $(COMMONOBJS)  $(LDFLAGS) -lgcrypt
	$(CC) $(CFLAGS) test_msg.c -o test_msg_bin $(COMMONOBJS) ../store/dummy.o $(LDFLAGS) -lgcrypt
	$(CC) $(CFLAGS) test_cert.c -o test_cert_bin $(COMMONOBJS) ../store/dummy.o $(LDFLAGS) -lgcrypt
	$(CC) $(CFLAGS) test_envelope.c -o test_envelope_bin $(COMMONOBJS) ../store/dummy.o $(LDFLAGS) -lgcrypt
	$(CC) $(CFLAGS) test_trust.c -o test_trust_bin $(COMMONOBJS) $(LDFLAGS)
	$(CC) $(CFLAGS) test_store.c -o test_store_bin $(COMMONOBJS) $(LDFLAGS) -lgcrypt
	$(CC) $(CFLAGS) test_query.c -o test_query_bin $(COMMONOBJS) $(LDFLAGS) -lgcrypt

clean:
	rm -vf test_*_bin
	rm -vf *.o

.PHONY: clean
