INCLUDES := `pkg-config --cflags libtasn1`
LIBS := `pkg-config --libs libtasn1`
LDFLAGS += $(LIBS)

all: compile

src:
	$(CC) $(CFLAGS) generate.c -o generate_asn1 $(LDFLAGS)

%.o: %_asn1_tab.c
	$(CC) $< -o $* $(LDFLAGS)

compile: generate defs_asn1_tab.o

generate: src
	./generate_asn1

clean:
	rm -vf *.o
	rm -vf *_tab.c
	rm -vf generate_asn1

.PHONY: clean
