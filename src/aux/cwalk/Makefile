all:
	mkdir -vp build
	cd build && cmake -DBUILD_SHARED_LIBS=1 ..
	cd build && make -j8
	cd build && make install DESTDIR=.
