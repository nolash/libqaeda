all:
	make -C src

test: all
	make -C src test

clean:
	make -C src clean

.PHONY: clean
