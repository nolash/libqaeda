#ifdef LQ_GPG
#define LQ_GPG

#define GPG_MIN_VERSION "1.10.2"
#define GPG_KEY_TYP 1

#include <gcrypt.h>
#include <rerr.h>

#include "lq/crypto.h"
#include "lq/io.h"
#include "debug.h"

#ifdef RERR
char *_rerr[7] = {
	"",
	"Crypto backend",
	"Auth fail",
	"Unlock fail",
	"Sign reject",
	"Resource fail",
	"No key found",
};
#endif

const char *gpgVersion = NULL;

struct gpg_store {
	gcry_sexp_t k;
	char fingerprint[LQ_FP_LEN];
	char public_key[LQ_PUBKEY_LEN];
	char path[LQ_PATH_MAX];
	char last_signature[LQ_SIG_LEN];
	char last_data[LQ_DIGEST_LEN];
};

int lq_crypto_init() {
#ifdef RERR
	rerr_register(RERR_PFX_GPG, "crypto", _rerr);
#endif
	char *p;
	size_t c;

	gpg = lq_zero(sizeof(struct gpg_store));
	if (gpg == NULL) {
		return ERR_MEM;
	}
	gpg->passphrase_digest_len = gcry_md_get_algo_dlen(GCRY_MD_SHA256);

	strcpy(gpg->path, path);
	c = strlen(gpg->path);
	p = gpg->path+c;
	if (*p != '/') {
		*p = '/';
		*(p+1) = 0;
	}

	return ERR_OK;
}

LQPrivKey* lq_privatekey_new(const char *seed, size_t seed_len, const char *passphrase, size_t passphrase_len) {

}

LQPrivKey* lq_privatekey_load(const char *passphrase, size_t passphrase_len) {
	LQPrivKey *o;

	o = lq_alloc(sizeof(LQPrivKey));
	if (o == NULL) {
		return NULL;
	}
	
	o->key_typ = GPG_KEY_TYP;
	o->key_state = LQ_KEY_INIT;
	o->impl = (void*)&gpg;
	return o;
}

size_t lq_publickey_bytes(LQPubKey *pubk, char **out) {

}

int lq_privatekey_lock(LQPrivKey *pk, const char *passphrase, size_t passphrase_len) {

}

int lq_privatekey_unlock(LQPrivKey *pk, const char *passphrase, size_t passphrase_len) {

}

LQSig* lq_privatekey_sign(LQPrivKey *pk, const char *msg, size_t msg_len, const char *salt) {

}

LQSig* lq_signature_from_bytes(const char *sig_data, size_t sig_len, LQPubKey *pubkey) {

}

size_t lq_signature_bytes(LQSig *sig, char **out) {

}

void lq_privatekey_free(LQPrivKey *pk) {
}

void lq_publickey_free(LQPubKey *pubk) {

}

void lq_signature_free(LQSig *sig) {

}

char *lq_publickey_fingerprint(LQPubKey *pubk) {

}

int lq_digest(const char *in, size_t in_len, char *out) {

}

#endif
