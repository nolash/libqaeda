all: core dummy

core: asn1
	make -C lq

asn1:
	make -C asn1
dummy:
	make -C crypto dummy
	make -C mem std

test: core dummy
	make -C test

clean:
	make -C asn1 clean
	make -C lq clean
	make -C test clean
	make -C mem clean
	make -C crypto clean
