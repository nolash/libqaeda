#include "lq/trust.h"
#include "lq/store.h"
#include "lq/err.h"


int lq_trust_check(LQPubKey *pubkey, LQStore *store, enum trust_mode_e mode, const char *flags) {
	int r;
	size_t l;
	int i;
	int ii;
	char m;
	int match;
	int match_req;
	char v[3];
	double z;
	char key_flags[(int)((LQ_TRUST_FLAG_BITS - 1)/8+1)];

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

	for (i = 0; i < LQ_TRUST_FLAG_BITS; i++) {
		ii = i % 8;
		if (ii == 0) {
			v[1] = *(flags + i);
			v[2] = key_flags[(int)(i / 8)];
			m = 0x80;
		}
		v[0] = v[1] & m;
		if (v[0] > 0) {
			match_req++;
			if ((v[2] & m) > 0) {
				match++;
				z += 1 / LQ_TRUST_FLAG_BITS;
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
		if (match < match_req) {
			return 0;
		}	
	}
	return (int)(z * 1000000.f);
}
