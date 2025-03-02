all: asn1 aux core dummy

core:
	make -C lq

aux:
	make -C aux

asn1:
	make -C asn1 all

dummy:
	make -C crypto dummy
	make -C mem std

test: all
	make -C test

clean:
	make -C asn1 clean
	make -C lq clean
	make -C test clean
	make -C mem clean
	make -C crypto clean

.PHONY: clean asn1 aux
