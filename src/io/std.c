#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

char *mktempdir(char *s) {
	return mkdtemp(s);
}

int lq_open(const char *pathname, int flags, int mode) {
	return open(pathname, flags, (mode_t)mode);
}

int lq_read(int f, void *buf, size_t c) {
	return read(f, buf, c);
}

void lq_close(int fd) {
	close(fd);
}
