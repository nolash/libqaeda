#ifndef LIBQAEDA_CRYPTO_H_
#define LIBQAEDA_CRYPTO_H_

#include <stddef.h>

#ifndef LQ_DIGEST_LEN
#define LQ_DIGEST_LEN 32
#endif

#ifndef LQ_PUBKEY_LEN
#define LQ_PUBKEY_LEN 65
#endif

#ifndef LQ_PRIVKEY_LEN
#define LQ_PRIVKEY_LEN 32
#endif

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

LQPrivKey* lq_privatekey_new(const char *seed, size_t seed_len);
LQPubKey* lq_publickey_new(const char *full);
LQPubKey* lq_publickey_from_privatekey(LQPrivKey *pk);
LQSig* lq_privatekey_sign(LQPrivKey *pk, const char *msg, size_t msg_len, const char *salt, size_t salt_len);
void lq_publickey_free(LQPubKey *pubk);
void lq_privatekey_free(LQPrivKey *pk);
void lq_signature_free(LQSig *sig);
int lq_digest(const char *in, size_t in_len, char *out);

#endif // LIBQAEDA_CRYPTO_H_
