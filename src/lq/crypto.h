#ifndef LIBQAEDA_CRYPTO_H_
#define LIBQAEDA_CRYPTO_H_

#include <stddef.h>

struct lq_privatekey_t {
	int key_typ;
	void *lokey;
	size_t lolen;
};
typedef struct lq_privatekey_t LQPrivKey;

struct lq_publickey_t {
	LQPrivKey *pk;
	void *lokey;
	size_t lolen;
};
typedef struct lq_publickey_t LQPubKey;

struct lq_signature_t {
	LQPubKey *pubkey;
	void *losig;
	size_t lolen;
};
typedef struct lq_signature_t LQSig;

LQPrivKey* lq_privatekey_new(char *seed, size_t seed_len);
LQPubKey* lq_publickey_new(char *full, size_t full_len);
LQPubKey* lq_publickey_from_privatekey(LQPrivKey *pk);
LQSig* lq_privatekey_sign(LQPrivKey *pk, char *sig, size_t *sig_len, const char *salt, size_t salt_len);
void lq_publickey_free(LQPubKey *pubk);
void lq_privatekey_free(LQPrivKey *pk);

#endif // LIBQAEDA_CRYPTO_H_
