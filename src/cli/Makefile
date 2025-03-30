INCLUDES := -I.. -I../lq -I../aux/include
CFLAGS +=  $(INCLUDES) -Wall
OBJFILES += ../asn1/*.o ../*.o ../lq/*.o ../store/file.o ../mem/std.o ../io/std.o ../crypto/gcrypt.o
LIBS := `pkg-config --libs libtasn1 libgcrypt libxdg-basedir` -L../aux/lib -llash -lcwalk
LDFLAGS += -L../aux/lib -L../ $(LIBS)

all:
	gcc $(CFLAGS) main.c -o a.out $(OBJFILES) $(LDFLAGS)

.PHONY: clean asn1 aux
