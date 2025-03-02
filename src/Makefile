all: asn1 core dummy

core:
	make -C lq

asn1:
	make -C asn1
dummy:
	make -C crypto dummy
	make -C mem std

test: core dummy
	make -C test
