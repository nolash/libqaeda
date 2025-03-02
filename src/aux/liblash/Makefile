VERSION = 0.0.1
DESTDIR := /usr/local
export DESTDIR
export VERSION

all: 
	$(MAKE) -C src all

shared:
	$(MAKE) -C src shared
src:
	$(MAKE) -C src

test: src
	$(MAKE) -C src test

clean:
	$(MAKE) -C src clean

archive:
	git archive --format=tar.gz HEAD > liblash-$(VERSION).tar.gz

install:
	mkdir -vp $(DESTDIR)/lib
	mkdir -vp $(DESTDIR)/include
	$(MAKE) -e -C src install

.PHONY: clean
