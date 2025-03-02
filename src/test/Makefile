OBJS := $(patsubst %.c,%.o,$(wildcard *.c))
INCLUDES := -I..
CFLAGS +=  $(INCLUDES) -Wall -g3
LIBS := `pkg-config --libs libtasn1` -L../aux/lib -llash ../asn1/defs_asn1_tab.o
LDFLAGS += $(LIBS)

all: build
	CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_crypto_bin
	CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_msg_bin
	CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_cert_bin
	
test: all

build:
	$(CC) $(CFLAGS) $(LDFLAGS) test_crypto.c -o test_crypto_bin ../crypto/dummy.o ../mem/std.o -lcheck
	$(CC) $(CFLAGS) $(LDFLAGS) test_msg.c -o test_msg_bin ../crypto/dummy.o ../mem/std.o ../lq/msg.o -lcheck
	$(CC) $(CFLAGS) $(LDFLAGS) test_cert.c -o test_cert_bin ../crypto/dummy.o ../mem/std.o ../lq/msg.o ../lq/cert.o -lcheck

