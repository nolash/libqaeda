all: asn1 dummy
	make -C lq

asn1:
	make -C asn1
dummy:
	make -C crypto dummy
	make -C mem std

test: dummy
	make -C test
