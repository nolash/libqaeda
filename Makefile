all: lib
	make -C src all

lib:
	make -C src lib

test: all
	make -C src test

clean:
	make -C src clean

#shared: lib
#	make -C src shared-gpg

.PHONY: clean
