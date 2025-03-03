#ifndef LIBQAEDA_TRUST_H_
#define LIBQAEDA_TRUST_H_

#ifndef LQ_TRUST_FLAG_BITS
#define LQ_TRUST_FLAG_BITS 13
#endif

#include "lq/crypto.h"
#include "lq/store.h"

/// Controls the way trust flags are tested against a public key's trust flags
enum trust_mode_e {
	TRUST_MATCH_NONE, ///< Ignore flags.
	TRUST_MATCH_ONE, ///< Success on first matched flag.
	TRUST_MATCH_BEST, ///< Match as many flags as possible.
	TRUST_MATCH_ALL, ///< Strictly match all flags.
};

/***
 * @brief Check whether a public key is known (exists in public key store) and optionally perform match its trust flags.
 *
 * The value of the "mode" parameter controls the behavior of this routine, as well as which return value to expect. In 
 * every case, a public key entry has to exist in the store for the routine not to fail.
 *
 * * TRUST_MATCH_NONE: Flags are ignored, if the public key exists 1000000 will be returned.
 * * TRUST_MATCH_ONE: If the public key exists and at least one flag matches, return 1000000
 * * TRUST_MATCH_BEST: If the public key exists, return a value in the range 1000000 >= v > 0 depending on the ratio of actually tested and matched flags. For example, if 3 out of 5 flags match, 600000 will be returned.
 * * TRUST_MATCH_ALL: Return 1000000 if the public key exists and all flags match.
 *
 * @param[in] Public key to match
 * @param[in] Store to search for public key record in
 * @param[in] Match mode
 * @param[in] Flags to match. Must have room for LQ_TRUST_FLAG_BITS bits, rounded up to the byte boundary.
 * @return If public key is not found, returns -1. If not, a value between 0 and 1000000 depending on the amount of relevant flag matches (see description above).
 * @see enum trust_mode_e
 */
int lq_trust_check(LQPubKey *pubkey, LQStore *store, enum trust_mode_e mode, const unsigned char *flags);

#endif // LIBQAEDA_TRUST_H_

