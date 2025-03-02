OBJS := $(patsubst %.c,%.o,$(wildcard *.c))
INCLUDES := -I..
CFLAGS +=  $(INCLUDES) -Wall -g3
LIBS := `pkg-config --libs libtasn1` -L../aux/lib -llash ../asn1/defs_asn1_tab.o
LDFLAGS += $(LIBS)

#%.o: %.c
#	$(CC) $(CFLAGS) $< -o $*_bin $(LDFLAGS) ../crypto/dummy.o ../mem/std.o -lcheck
#	./$*_bin

#all: $(OBJS)
all: build
	CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_crypto_bin
	CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_msg_bin
	
test: all

build:
	$(CC) $(CFLAGS) $(LDFLAGS) test_crypto.c -o test_crypto_bin ../crypto/dummy.o ../mem/std.o -lcheck
	$(CC) $(CFLAGS) $(LDFLAGS) test_msg.c -o test_msg_bin ../crypto/dummy.o ../mem/std.o ../lq/msg.o -lcheck

