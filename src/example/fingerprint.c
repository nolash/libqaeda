#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <hex.h>
#include <lq/base.h>
#include <lq/crypto.h>


int main(int argc, char **argv) {
	int f;
	int r;
	size_t c;
	int l;
	char b[LQ_CRYPTO_BUFLEN];
	char *p;
	char *fp;
	LQPubKey *pubk;

	lq_init();
	f = open(*(argv+1), O_RDONLY);
	if (f < 0) {
		lq_finish();
		return 1;
	}

	c = 0;
	l = LQ_PUBKEY_LEN;
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

	pubk = lq_publickey_new(b);
	if (pubk == NULL) {
		lq_finish();
		return 1;
	}
	c = lq_publickey_fingerprint(pubk, &fp);
	if (c == 0) {
		lq_publickey_free(pubk);
		lq_finish();
		return 1;
	}
	b2h((unsigned char*)fp, c, (unsigned char*)b);
	p = (char*)b;
	r = -1;
	while (r) {
		r = write(0, b, c);
		c -= (size_t)r;
		p += r;
	}	


	lq_publickey_free(pubk);
	lq_finish();
}
