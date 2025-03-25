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
	const char *v;

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
	int r;
	LQPrivKey *o;

	o = privatekey_alloc(seed, seed_len, passphrase, passphrase_len);
	if (o == NULL) {
		return NULL;
	}
	r = lq_privatekey_lock(o, passphrase, passphrase_len);
	if (r) {
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
	if (pk == NULL) {
		return ERR_INIT;
	}
	if ((pk->key_state & LQ_KEY_LOCK) > 0) {
		return ERR_NOOP;
	}
	pk->key_state |= LQ_KEY_LOCK;
	return ERR_OK;
}

int lq_privatekey_unlock(LQPrivKey *pk, const char *passphrase, size_t passphrase_len) {
	char b;

	if (pk == NULL) {
		return ERR_INIT;
	}
	if ((pk->key_state & LQ_KEY_LOCK) == 0) {
		return ERR_NOOP;
	}
	b = LQ_KEY_LOCK;
	pk->key_state &= ~b;
	return ERR_OK;
}

// SIGNATURE SECTION
//
//int sign_with(struct gpg_store *gpg, char *data, size_t data_len, const char *passphrase, const char *fingerprint) {
//	int r;
//	size_t c;
//	gcry_sexp_t pnt;
//	gcry_sexp_t msg;
//	gcry_sexp_t sig;
//	gcry_error_t e;
//	char *p;
//
//
//	if (fingerprint == NULL) {
//		r = gpg_key_load(gpg, passphrase, KEE_GPG_FIND_MAIN, NULL);
//	} else {
//		r = gpg_key_load(gpg, passphrase, KEE_GPG_FIND_FINGERPRINT, fingerprint);
//	}
//	if (r) {
//		return 1;
//	}
//		 
//	c = 0;
//	e = gcry_sexp_build(&msg, &c, "(data(flags eddsa)(hash-algo sha512)(value %b))", 64, gpg->last_data);
//	if (e != GPG_ERR_NO_ERROR) {
//		return 1;
//	}
//}

static int sign(struct gpg_store *gpg, const char *data, size_t data_len, const char *salt) {
	int r;
	size_t c;
	char *p;
	gcry_sexp_t pnt;
	gcry_sexp_t msg;
	gcry_sexp_t sig;
	gcry_error_t e;

	r = calculate_digest_algo(data, data_len, gpg->last_data, GCRY_MD_SHA512);
	if (r) {
		return 1;
	}

	c = 0;
	e = gcry_sexp_build(&msg, &c, "(data(flags eddsa)(hash-algo sha512)(value %b))", 64, gpg->last_data);
	if (e != GPG_ERR_NO_ERROR) {
		return 1;
	}

	e = gcry_pk_sign(&sig, msg, gpg->k);
	if (e != GPG_ERR_NO_ERROR) {
		return 1;
	}

	// retrieve r and write it
	pnt = NULL;
	pnt = gcry_sexp_find_token(sig, "r", 1);
	if (pnt == NULL) {
		return 1;
	}
	c = LQ_POINT_LEN;
	p = (char*)gcry_sexp_nth_data(pnt, 1, &c);
	if (p == NULL) {
		return 1;
	}
	lq_cpy(gpg->last_signature, p, c);

	// retrieve s and write it
	pnt = NULL;
	pnt = gcry_sexp_find_token(sig, "s", 1);
	if (pnt == NULL) {
		return 1;
	}
	c = LQ_POINT_LEN;
	p = (char*)gcry_sexp_nth_data(pnt, 1, &c);
	if (p == NULL) {
		return 1;
	}
	lq_cpy(gpg->last_signature + LQ_POINT_LEN, p, c);

	//gcry_sexp_release(gpg->k);

	return 0;
}

LQSig* lq_privatekey_sign(LQPrivKey *pk, const char *data, size_t data_len, const char *salt) {
	int r;
	struct gpg_store *gpg;
	LQSig *sig;
	char digest[LQ_DIGEST_LEN];

	if ((pk->key_state & LQ_KEY_LOCK) > 0) {
		return NULL;
	}

	lq_digest(data, strlen(data), (char*)digest);
	gpg = (struct gpg_store*)pk->impl;

	r = sign(gpg, digest, LQ_DIGEST_LEN, salt);
	if (r != ERR_OK) {
		return NULL;
	}

	sig = lq_alloc(sizeof(LQSig));
	sig->pubkey = lq_publickey_from_privatekey(pk);
	if (sig->pubkey == NULL) {
		lq_free(sig);
		return NULL;
	}
	sig->impl= gpg->last_signature;
	return sig;
}

LQSig* lq_signature_from_bytes(const char *sig_data, size_t sig_len, LQPubKey *pubkey) {

}

size_t lq_signature_bytes(LQSig *sig, char **out) {
	*out = sig->impl;
	return LQ_SIGN_LEN;
}

int lq_signature_verify(LQSig *sig, const char *data, size_t data_len) {
	int r;
	size_t c;
	gcry_mpi_t sig_r;
	gcry_mpi_t sig_s;
	gcry_error_t err;
	gcry_sexp_t sigx;
	gcry_sexp_t msgx;
	gcry_sexp_t pubkey;
	struct gpg_store *gpg;
	char digest[LQ_DIGEST_LEN];

	if (sig->pubkey == NULL) {
		return ERR_NOENT;
	}

	gpg = (struct gpg_store*)sig->pubkey->impl;
	c = 0;
	err = gcry_sexp_build(&pubkey, &c, "(key-data(public-key(ecc(curve Ed25519)(q %b))))", LQ_PUBKEY_LEN, gpg->public_key);
	if (err != GPG_ERR_NO_ERROR) {
		return ERR_CRYPTO;
	}

	c = 0;
	err = gcry_mpi_scan(&sig_r, GCRYMPI_FMT_STD, sig->impl, LQ_POINT_LEN, &c);
	if (err != GPG_ERR_NO_ERROR) {
		return ERR_CRYPTO;
	}
	if (c != 32) {
		return ERR_CRYPTO;
	}

	c = 0;
	err = gcry_mpi_scan(&sig_s, GCRYMPI_FMT_STD, sig->impl + LQ_POINT_LEN, LQ_POINT_LEN, &c);
	if (err != GPG_ERR_NO_ERROR) {
		return ERR_CRYPTO;
	}
	if (c != 32) {
		return ERR_CRYPTO;
	}

	c = 0;
	err = gcry_sexp_build(&sigx, &c, "(sig-val(eddsa(r %m)(s %m)))", sig_r, sig_s);
	if (err != GPG_ERR_NO_ERROR) {
		return ERR_CRYPTO;
	}

	r = calculate_digest_algo(data, data_len, digest, GCRY_MD_SHA512);
	if (r) {
		return ERR_CRYPTO;
	}

	c = 0;
	err = gcry_sexp_build(&msgx, &c, "(data(flags eddsa)(hash-algo sha512)(value %b))", LQ_DIGEST_LEN, digest);
	if (err != GPG_ERR_NO_ERROR) {
		return ERR_CRYPTO;
	}

	err = gcry_pk_verify(sigx, msgx, pubkey);
	if (err != GPG_ERR_NO_ERROR) {
		return ERR_ENCODING;
	}

	return ERR_OK;
}

void lq_privatekey_free(LQPrivKey *pk) {
	lq_free(pk->impl);
	lq_free(pk);
}

void lq_publickey_free(LQPubKey *pubk) {
	lq_free(pubk);
}

void lq_signature_free(LQSig *sig) {
	lq_free(sig->pubkey);
	lq_free(sig);
}

char *lq_publickey_fingerprint(LQPubKey *pubk) {
	struct gpg_store *gpg;
	char *p;

	gpg = (struct gpg_store*)pubk->impl;
	return gpg->fingerprint;
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
	lq_cpy(gpg->public_key, full, LQ_PUBKEY_LEN);

	r = (char*)gcry_pk_get_keygrip(gpg->k, (unsigned char*)gpg->fingerprint);
	if (r == NULL) {
		return NULL;
	}

	pubk->impl = (void*)gpg;
	pubk->key_typ = GPG_KEY_TYP;
	pubk->pk = NULL;
	return pubk;
}

#endif
