all: dummy
	make -C lq

dummy:
	make -C crypto dummy
	make -C mem std

test: dummy
	make -C test
