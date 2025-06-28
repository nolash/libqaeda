INCLUDES := -I.. -I../aux/include
CFLAGS +=  $(INCLUDES) -Wall -DRERR
LIBS := `pkg-config --libs libtasn1 libgcrypt` -L../aux/lib -L.. -lqaeda
LDFLAGS := $(LIBS)

all:
	#$(CC) $(CFLAGS) -o attach attach.c $(LDFLAGS)
	$(CC) $(CFLAGS) -o mat mat.c $(LDFLAGS)
