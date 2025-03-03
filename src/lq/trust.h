#ifndef LIBQAEDA_TRUST_H_
#define LIBQAEDA_TRUST_H_

#ifndef LQ_TRUST_FLAG_BITS
#define LQ_TRUST_FLAG_BITS 8
#endif

#include "lq/crypto.h"
#include "lq/store.h"

enum trust_mode_e {
	TRUST_MATCH_NONE,
	TRUST_MATCH_ONE,
	TRUST_MATCH_BEST,
	TRUST_MATCH_ALL,
};

int lq_trust_check(LQPubKey *pubkey, LQStore *store, enum trust_mode_e mode, const char *flags);

#endif // LIBQAEDA_TRUST_H_

