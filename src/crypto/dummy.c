#include "lq/crypto.h"
#include "lq/mem.h"

LQPrivKey* lq_privatekey_new(char *seed, size_t seed_len) {
	LQPrivKey *pk;

	pk = lq_alloc(sizeof(LQPrivKey));
	pk->lokey = lq_alloc(seed_len);
	lq_cpy(pk->lokey, seed, seed_len);
	pk->lolen = seed_len;
	return pk;
}

void lq_privatekey_free(LQPrivKey *pk) {
	lq_free(pk->lokey);
	lq_free(pk);
}

LQPubKey* lq_publickey_new(char *full, size_t full_len) {
	LQPubKey *pubk;

	pubk = lq_alloc(sizeof(LQPubKey));
	lq_set(pubk->pk, 0, sizeof(LQPrivKey));
	pubk->lokey = lq_alloc(full_len);
	lq_cpy(pubk->lokey, full, full_len);
	pubk->lolen = full_len;

	return pubk;
}

LQPubKey* lq_publickey_from_privatekey(LQPrivKey *pk) {
	LQPubKey *pubk;

	pubk = lq_alloc(sizeof(LQPubKey));

	return pubk;
}

LQSig* lq_privatekey_sign(LQPrivKey *pk, char *sig, size_t *sig_len, const char *salt, size_t salt_len) {
	return NULL;
}

void lq_publickey_free(LQPubKey *pubk) {
	lq_free(pubk->lokey);
	lq_free(pubk);
}
