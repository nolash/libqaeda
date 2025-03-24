#ifdef LQ_GPG

#define GPG_MIN_VERSION "1.10.2"
#define GPG_KEY_TYP 1

#include <gcrypt.h>
#include <rerr.h>
#include <llog.h>

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
		if (v == NULL) {
			return ERR_NOCRYPTO;
		}
	}
	gpg_version = v;
	debug_dbg_x("gpg", "using gpg", 1, MORGEL_TYP_STR, 0, "version", gpg_version);

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

static int key_apply_public(struct gpg_store *gpg, gcry_sexp_t key) {
	char *p;
	size_t c;
	gcry_sexp_t pubkey;

	pubkey = gcry_sexp_find_token(key, "public-key", 10);
	if (pubkey == NULL) {
		return debug_logerr(LLOG_ERROR, ERR_CRYPTO, NULL);
	}
	pubkey = gcry_sexp_find_token(pubkey, "q", 1);
	if (pubkey == NULL) {
		return debug_logerr(LLOG_ERROR, ERR_CRYPTO, NULL);
	}
	c = LQ_PUBKEY_LEN;
	p = (char*)gcry_sexp_nth_data(pubkey, 1, &c);
	if (p == NULL) {
		return debug_logerr(LLOG_ERROR, ERR_CRYPTO, NULL);
	}
	lq_cpy(gpg->public_key, p, LQ_PUBKEY_LEN);
	return ERR_OK;
}

static int key_create(struct gpg_store *gpg) {
	int r;
	const char *p;
	const char *sexp_quick = "(genkey(ecc(flags eddsa)(curve Ed25519)))";
	//char *pv;
	gcry_sexp_t in;
	gcry_error_t e;

	e = gcry_sexp_new(&in, (const void*)sexp_quick, strlen(sexp_quick), 0);
	if (e) {
		p = gcry_strerror(e);
		return debug_logerr(LLOG_ERROR, ERR_KEYFAIL, (char*)p);
	}
	e = gcry_pk_genkey(&gpg->k, in);
	if (e) {
		p = gcry_strerror(e);
		return debug_logerr(LLOG_ERROR, ERR_KEYFAIL, (char*)p);
	}
	p = (char*)gcry_pk_get_keygrip(gpg->k, (unsigned char*)gpg->fingerprint);
	if (p == NULL) {
		p = gcry_strerror(e);
		return debug_logerr(LLOG_ERROR, ERR_KEYFAIL, (char*)p);
	}

	r = key_apply_public(gpg, gpg->k);
	if (r) {
		return debug_logerr(LLOG_ERROR, ERR_KEYFAIL, NULL);
	}

	return ERR_OK;
}


static LQPrivKey* privatekey_alloc(const char *seed, size_t seed_len, const char *passphrase, size_t passphrase_len) {
	int r;
	LQPrivKey *o;
	struct gpg_store *gpg;

	// allocate private key memory
	o = lq_alloc(sizeof(LQPrivKey));
	if (o == NULL) {
		return NULL;
	}

	// allocate gpg internal private key memory
	gpg = lq_alloc(sizeof(struct gpg_store));
	if (gpg == NULL) {
		lq_free(o);
		return NULL;
	}

	// create the underlying private key.
	r = key_create(gpg);
	if (r) {
		lq_free(gpg);
		lq_free(o);
		return NULL;
	}

	// 
	o->impl = (void*)gpg;
	o->key_typ = GPG_KEY_TYP;
	o->key_state = LQ_KEY_INIT;
	return o;
}

LQPrivKey* lq_privatekey_new(const char *seed, size_t seed_len, const char *passphrase, size_t passphrase_len) {
	LQPrivKey *o;

	o = privatekey_alloc(seed, seed_len, passphrase, passphrase_len);
	if (o == NULL) {
		return NULL;
	}
	return o;	
}

LQPrivKey* lq_privatekey_load(const char *passphrase, size_t passphrase_len) {
	return NULL;
}

size_t lq_publickey_bytes(LQPubKey *pubk, char **out) {
	struct gpg_store *gpg;

	gpg = (struct gpg_store*)pubk->impl;
	*out = gpg->public_key;
	return LQ_PUBKEY_LEN;
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
	lq_free(pubk);
}

void lq_signature_free(LQSig *sig) {

}

char *lq_publickey_fingerprint(LQPubKey *pubk) {
	char *p;

}

LQPubKey* lq_publickey_from_privatekey(LQPrivKey *pk) {
	struct gpg_store *gpg;
	LQPubKey *pubk;

	gpg = (struct gpg_store*)pk->impl;
	pubk = lq_publickey_new(gpg->public_key);

	return pubk;
}

LQPubKey* lq_publickey_new(const char *full) {
	const char *r;
	gcry_error_t e;
	size_t c;
	LQPubKey *pubk;
	struct gpg_store *gpg;

	pubk = lq_alloc(sizeof(LQPubKey));
	gpg = lq_alloc(sizeof(struct gpg_store));

	lq_zero(gpg, sizeof(struct gpg_store));
	c = 0;
	e = gcry_sexp_build(&gpg->k, &c, "(key-data(public-key(ecc(curve Ed25519)(q %b))))", LQ_PUBKEY_LEN, full);
	if (e != GPG_ERR_NO_ERROR) {
		return NULL;
	}

	r = (char*)gcry_pk_get_keygrip(gpg->k, (unsigned char*)gpg->fingerprint);
	if (r == NULL) {
		return NULL;
	}

	pubk->impl = (void*)gpg;
	pubk->key_typ = GPG_KEY_TYP;
	pubk->pk = NULL;
	return pubk;
}

// DIGEST SECTION

int calculate_digest_algo(const char *in, size_t in_len, char *out, enum gcry_md_algos algo) {
	gcry_error_t e;
	gcry_md_hd_t h;
	unsigned char *v;
	static unsigned int digest_len;

	if (algo == GCRY_MD_NONE) {
		algo = GCRY_MD_SHA256;
	}
	digest_len = gcry_md_get_algo_dlen(algo);

	e = gcry_md_open(&h, algo, GCRY_MD_FLAG_SECURE);
	if (e) {
		return ERR_ENCODING;
	}

	gcry_md_write(h, in, in_len);
	v = gcry_md_read(h, 0);
	lq_cpy(out, v, digest_len);
	gcry_md_close(h);
	return ERR_OK;
}

//int calculate_digest(const char *in, size_t in_len, char *out) {
//	return calculate_digest_algo(in, in_len, out, GCRY_MD_NONE);
//}

int lq_digest(const char *in, size_t in_len, char *out) {
	return calculate_digest_algo(in, in_len, out, GCRY_MD_NONE);
}

#endif
