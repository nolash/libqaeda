OBJS := $(patsubst %.c,%.o,$(wildcard *.c))
INCLUDES := -I.. -I../aux/include
CFLAGS +=  $(INCLUDES) -Wall -g3
LIBS := `pkg-config --libs libtasn1` -L../aux/lib -llash -lm -lcheck -lhashmap ../asn1/defs_asn1_tab.o
LDFLAGS += $(LIBS)

all: build
	CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_crypto_bin
	CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_msg_bin
	CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_cert_bin
	CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_trust_bin
	
test: all

build:
	$(CC) $(CFLAGS) test_crypto.c -o test_crypto_bin ../crypto/dummy.o ../mem/std.o $(LDFLAGS) 
	$(CC) $(CFLAGS) test_msg.c -o test_msg_bin ../crypto/dummy.o ../mem/std.o ../store/dummy.o ../store/file.o ../io/std.o ../lq/msg.o $(LDFLAGS)
	$(CC) $(CFLAGS) test_cert.c -o test_cert_bin ../crypto/dummy.o ../mem/std.o ../store/dummy.o ../store/file.o ../io/std.o ../lq/msg.o ../lq/cert.o $(LDFLAGS)
	$(CC) $(CFLAGS) test_trust.c -o test_trust_bin ../crypto/dummy.o ../mem/std.o ../store/mem.o ../lq/trust.o $(LDFLAGS)

clean:
	rm -vf test_*_bin
	rm -vf *.o

.PHONY: clean
