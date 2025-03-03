#include "lq/trust.h"
#include "lq/store.h"
#include "lq/err.h"


int lq_trust_check(LQPubKey *pubkey, LQStore *store, enum trust_mode_e mode, const unsigned char *flags) {
	int r;
	size_t l;
	int i;
	int ii;
	unsigned char m;
	int match;
	int match_req;
	unsigned char v[3];
	double z;
	unsigned char key_flags[(int)((LQ_TRUST_FLAG_BITS - 1)/8+1)];

	l = (int)((LQ_TRUST_FLAG_BITS - 1)/8+1);
	r = store->get(LQ_CONTENT_KEY, store, pubkey->lokey, pubkey->lolen, key_flags, &l);
	if (r != ERR_OK) {
		return -1;
	}

	if (mode == TRUST_MATCH_NONE || LQ_TRUST_FLAG_BITS == 0) {
		return 1000000;
	}

	match = 0;
	match_req = 0;
	z = 0.f;
	m = 0;
	ii = 0;

	for (i = 0; i < LQ_TRUST_FLAG_BITS; i++) {
		if (m == 0) {
			v[1] = *(flags + ii);
			v[2] = key_flags[ii];
			m = 0x80;
			ii++;
		}
		v[0] = v[1] & m;
		if (v[0] > 0) {
			match_req++;
			if ((v[2] & m) > 0) {
				match++;
			}
		}
		if (match > 0) {
			if (mode == TRUST_MATCH_ONE) {
				return 1000000;
			}
		}
		m >>= 1;
	}
	if (mode == TRUST_MATCH_ALL) { 
		if (match != match_req) {
			return 0;
		}
		return 1000000;
	}
	z = (double)match / (double)match_req;
	return (int)(z * 1000000);
}
