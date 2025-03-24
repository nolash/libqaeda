OBJS := $(patsubst %.c,%.o,$(wildcard *.c))
INCLUDES := -I.. -I../aux/include
CFLAGS += $(INCLUDES) -Wall -g3
LIBS := ../asn1/defs_asn1_tab.o `pkg-config --libs libtasn1` -L../aux/lib -llash
#LDFLAGS := -lcheck -lsubunit -lm $(LIBS)
LDFLAGS := -lcheck $(LIBS)

all: build
	CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_debug_bin
	CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_config_bin
	CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_crypto_bin
	CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_msg_bin
	CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_cert_bin
	CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_trust_bin

test: all

build:
	$(CC) $(CFLAGS) test_debug.c -o test_debug_bin ../debug.o $(LDFLAGS)
	$(CC) $(CFLAGS) test_config.c -o test_config_bin ../lq/config.o ../mem/std.o $(LDFLAGS)
	#$(CC) $(CFLAGS) test_crypto.c -o test_crypto_bin ../crypto/dummy.o ../mem/std.o $(LDFLAGS)
	$(CC) $(CFLAGS) test_crypto.c -o test_crypto_bin ../crypto/gcrypt.o ../debug.o ../mem/std.o ../lq/config.o $(LDFLAGS) -lgcrypt
	$(CC) $(CFLAGS) test_msg.c -o test_msg_bin ../crypto/dummy.o ../mem/std.o ../store/dummy.o ../store/file.o ../io/std.o ../lq/msg.o $(LDFLAGS)
	$(CC) $(CFLAGS) test_cert.c -o test_cert_bin ../crypto/dummy.o ../mem/std.o ../store/dummy.o ../store/file.o ../io/std.o ../lq/msg.o ../lq/cert.o $(LDFLAGS)
	$(CC) $(CFLAGS) test_trust.c -o test_trust_bin ../crypto/dummy.o ../mem/std.o ../store/mem.o ../lq/trust.o -lhashmap $(LDFLAGS)

clean:
	rm -vf test_*_bin
	rm -vf *.o

.PHONY: clean
