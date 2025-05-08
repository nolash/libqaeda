OBJS := $(patsubst %.c,%.o,$(wildcard *.c))
INCLUDES := -I.. -I../aux/include `pkg-config --cflags libtasn1 libgcrypt`
CFLAGS += $(INCLUDES) -Wall -g3
#LIBS := ../asn1/defs_asn1_tab.o `pkg-config --libs libtasn1 libgcrypt` -L../aux/lib -llash -lhashmap
LIBS := ../asn1/defs_asn1_tab.o `pkg-config --libs libtasn1 libgcrypt` -L.. -L../aux/lib -lqaeda -lhashmap
#LDFLAGS := -lcheck -lsubunit -lm $(LIBS)
#LDFLAGS := -lcheck $(LIBS)
LDFLAGS := $(LIBS)
#COMMONOBJS = ../mem/std.o ../lq/config.o ../lq/err.o ../lq/base.o ../debug.o

all:
	$(CC) $(CFLAGS) query.c -o query_bin $(COMMONOBJS) $(LDFLAGS) -lgcrypt
	$(CC) $(CFLAGS) verify.c -o verify_bin $(COMMONOBJS) $(LDFLAGS) -lgcrypt
