#ifdef LQ_GPG

#define GPG_MIN_VERSION "1.10.2"
#define GPG_KEY_TYP 1

#include <gcrypt.h>
#include <rerr.h>

#include "lq/crypto.h"
#include "lq/io.h"
#include "lq/mem.h"
#include "lq/config.h"
#include "lq/err.h"
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

struct gpg_store {
	gcry_sexp_t k;
	char fingerprint[LQ_FP_LEN];
	char public_key[LQ_PUBKEY_LEN];
	char last_signature[LQ_SIGN_LEN];
	char last_data[LQ_DIGEST_LEN];
};

static const char *gpg_version = NULL;
static int gpg_cfg_idx_dir;
static int gpg_passphrase_digest_len;

int lq_crypto_init() {
#ifdef RERR
	rerr_register(RERR_PFX_GPG, "crypto", _rerr);
#endif
	//char *p;
	//size_t c;
	int r;
	char *v;

	if (gpg_version == NULL) {
		v = gcry_check_version(GPG_MIN_VERSION);
		//if (v == nullptr) {
		if (v == NULL) {
			return ERR_NOCRYPTO;
		}
	}
	gpg_version = v;
	//sprintf(d, "Using gpg version: %s", gpgVersion);
	debug_dbg_x("gpg", "using gpg", MORGEL_TYP_STR, 0, "version", gpg_version);

//	gpg = lq_zero(sizeof(struct gpg_store));
//	if (gpg == NULL) {
//		return ERR_MEM;
//	}
//	gpg->passphrase_digest_len = gcry_md_get_algo_dlen(GCRY_MD_SHA256);
	gpg_passphrase_digest_len = gcry_md_get_algo_dlen(GCRY_MD_SHA256);
	gpg_cfg_idx_dir = lq_config_register(LQ_TYP_STR, "CRYPTODIR");

//	strcpy(gpg->path, path);
//	c = strlen(gpg->path);
//	p = gpg->path+c;
//	if (*p != '/') {
//		*p = '/';
//		*(p+1) = 0;
//	}

	return ERR_OK;
}

LQPrivKey* lq_privatekey_new(const char *seed, size_t seed_len, const char *passphrase, size_t passphrase_len) {

}

LQPrivKey* lq_privatekey_load(const char *passphrase, size_t passphrase_len) {
	LQPrivKey *o;
	struct gpg_store *gpg;

	// allocate private key memory
	o = lq_alloc(sizeof(LQPrivKey));
	if (o == NULL) {
		return NULL;
	}

	// allocate gpg internal private key memory
	o->impl = lq_alloc(sizeof(struct gpg_store));
	if (o->impl == NULL) {
		lq_free(o);
		return NULL;
	}

	// 	
	o->key_typ = GPG_KEY_TYP;
	o->key_state = LQ_KEY_INIT;
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
	lq_free(pk->impl);
	lq_free(pk);
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
