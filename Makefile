all:
	make -C src all

lib:
	make -C src lib

test: all
	make -C src test

clean:
	make -C src clean

.PHONY: clean
