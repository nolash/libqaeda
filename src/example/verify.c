#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <llog.h>
#include <lq/cert.h>
#include <lq/base.h>
#include "debug.h"


int main(int argc, char **argv) {
	int f;
	int r;
	int c;
	int l;
	char b[LQ_CRYPTO_BUFLEN];
	LQCert *cert;

	lq_init();
	f = open(*(argv+1), O_RDONLY);
	if (f < 0) {
		lq_finish();
		return 1;
	}

	c = 0;
	l = LQ_CRYPTO_BUFLEN;
	while (1) {
		r = read(f, b, l);
		if (r < 1) {
			break;
		}
		l -= r;
		c += r;
	}
	close(f);
	if (r < 0) {
		lq_finish();
		return errno;
	}

	r = lq_certificate_deserialize(&cert, NULL, b, c);
	if (r) {
		debug_logerr(LLOG_ERROR, r, "deserialize err");
	}

	lq_finish();
	return r;
}
