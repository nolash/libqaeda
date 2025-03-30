#ifdef LQ_GPG

#define GPG_MIN_VERSION "1.10.2"
#define GPG_KEY_TYP 1

#include <gcrypt.h>
#include <rerr.h>
#include <llog.h>
#include <hex.h>

#include "lq/crypto.h"
#include "lq/io.h"
#include "lq/mem.h"
#include "lq/config.h"
#include "lq/err.h"
#include "lq/store.h"
#include "debug.h"

#define CHACHA20_KEY_LENGTH_BYTES 32
#define CHACHA20_NONCE_LENGTH_BYTES 12

/// Lookup mode for key in store.
enum gpg_find_mode_e {
	GPG_FIND_MAIN, ///< Use default key filename.
	GPG_FIND_ORCREATE, ///< Create a new key if not found.
	GPG_FIND_FINGERPRINT, ///< Load only the key matching the fingerprint.
};

/**
 * gcrypt implementation of the crypto interface.
 *
 * The same structure is used in both LQPrivKey and LQPubKey.
 *
 */
struct gpg_store {
	gcry_sexp_t k; ///< S-expression representing the current object type.
	char fingerprint[LQ_FP_LEN]; ///< Fingerprint, used for LQPubKey.
	char public_key[LQ_PUBKEY_LEN]; ///< Literal, uncompressed public key bytes. Used in LQPubKey.
	char last_signature[LQ_SIGN_LEN]; ///< Stores the latest signature data generated by lq_privatekey_sign.
	char last_data[LQ_DIGEST_LEN]; ///< Stores the last digest data that was signed using lq_privatekey_sign.
};

/// store gpg library version.
static const char *gpg_version = NULL;

/// directory holding crypto keys.
static int gpg_cfg_idx_dir;

/// default digest id.
static int gpg_passphrase_digest = GCRY_MD_SHA256;

/// digest length of hashed password.
static int gpg_passphrase_digest_len;

/// zero fp value
const static char gpg_fingerprint_zero[LQ_FP_LEN];

const static char gpg_default_store_key;

static LQStore *gpg_key_store;

/**
 * Verifies that installed gpg version is supported.
 * Sets up crypto keys dir and sets passphrase digest length.
 *
 * \todo replace path massage with cwalk lib
 */
int lq_crypto_init(const char *base) {
	int r;
	int l;
	char *v;
	char path[LQ_PATH_MAX];

	if (gpg_version == NULL) {
		v = (char*)gcry_check_version(GPG_MIN_VERSION);
		if (v == NULL) {
			return ERR_NOCRYPTO;
		}
	}
	gpg_version = v;
	debug_x(LLOG_DEBUG, "gpg", "using gpg", 1, MORGEL_TYP_STR, 0, "version", gpg_version);

	//gpg_passphrase_digest_len = gcry_md_get_algo_dlen(GCRY_MD_SHA256);
	gpg_passphrase_digest_len = gcry_md_get_algo_dlen(GCRY_MD_SHA512);
	gpg_cfg_idx_dir = lq_config_register(LQ_TYP_STR, "CRYPTODIR");

	v = path;
	l = strlen(base);
	lq_cpy(v, base, l);
	v += l;
	if (*v != '/') {
		*v = '/';
		*(v+1) = 0;
	}

	r = lq_config_set(gpg_cfg_idx_dir, path);
	if (r) {
		return ERR_FAIL;
	}
	gpg_key_store = lq_store_new(path);
	if (gpg_key_store == NULL) {
		return ERR_STORE_AVAIL;
	}

	return ERR_OK;
}

size_t get_padsize(size_t insize, size_t blocksize) {
	size_t c;
	size_t l;
	size_t m;

	c = insize + 1;
	l = c / blocksize;
	m = c % blocksize;
	if (m) {
		l++;
	}
	return l * blocksize;
}

static void padb(char *data, size_t outsize, size_t insize) {
	gcry_randomize(data + insize, outsize - insize, GCRY_STRONG_RANDOM);
}

static void pad(char *indata_raw, size_t outsize, const char *indata) { //std::string indata) {
	int l;

	strcpy(indata_raw, indata);
	l = strlen(indata) + 1;
	padb(indata_raw, outsize, l);
}

static int create_handle(gcry_cipher_hd_t *h, const char *key, const char *nonce) {
	const char *p;
	gcry_error_t e;

	e = gcry_cipher_open(h, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_POLY1305, GCRY_CIPHER_SECURE);
	if (e) {
		p = gcry_strerror(e);
		return debug_logerr(LLOG_ERROR, ERR_FAIL, (char*)p);
	}
	e = gcry_cipher_setkey(*h, key, CHACHA20_KEY_LENGTH_BYTES);
	if (e) {
		return ERR_FAIL;
	}
	e = gcry_cipher_setiv(*h, nonce, CHACHA20_NONCE_LENGTH_BYTES);
	if (e) {
		return ERR_FAIL;
	}
	return ERR_OK;
}


static void free_handle(gcry_cipher_hd_t *h) {
	gcry_cipher_close(*h);
}

int encryptb (char *ciphertext, size_t ciphertext_len, const char *indata, size_t indata_len, const char *key, const char *nonce) {
	const char *p;
	int r;
	gcry_cipher_hd_t h;
	gcry_error_t e;
	char indata_raw[ciphertext_len];

	r = create_handle(&h, key, nonce);
	if (r) {
		return debug_logerr(LLOG_ERROR, ERR_CIPHER, "encrypt handle (bin)");
	}
	lq_cpy(indata_raw, indata, indata_len);
	padb(indata_raw, ciphertext_len, indata_len);
	e = gcry_cipher_encrypt(h, (unsigned char*)ciphertext, ciphertext_len, (const unsigned char*)indata_raw, ciphertext_len);
	if (e) {
		free_handle(&h);
		p = gcry_strerror(e);
		return debug_logerr(LLOG_ERROR, ERR_CIPHER, (char*)p);
	}

	free_handle(&h);

	return ERR_OK;
}

int encrypt(char *ciphertext, size_t ciphertext_len, const char *indata, const char *key, const char *nonce) {
	char *p;
	int r;
	gcry_cipher_hd_t h;
	gcry_error_t e;
	char indata_raw[ciphertext_len];

	r = create_handle(&h, key, nonce);
	if (r) {
		return debug_logerr(LLOG_ERROR, ERR_CIPHER, "encrypt handle (str)");
	}

	pad(indata_raw, ciphertext_len, indata);
	e = gcry_cipher_encrypt(h, (unsigned char*)ciphertext, ciphertext_len, (const unsigned char*)indata_raw, ciphertext_len);
	if (e) {
		free_handle(&h);
		p = (char*)gcry_strerror(e);
		return debug_logerr(LLOG_ERROR, ERR_CIPHER, p);
	}

	free_handle(&h);

	return ERR_OK;
}

int decryptb(char *outdata, const char *ciphertext, size_t ciphertext_len, const char *key, const char *nonce) {
	char *p;
	int r;
	gcry_cipher_hd_t h;
	gcry_error_t e;

	r = create_handle(&h, key, nonce);
	if (r) {
		return debug_logerr(LLOG_ERROR, ERR_CIPHER, "decrypt handle (bin)");
	}

	e = gcry_cipher_decrypt(h, outdata, ciphertext_len, ciphertext, ciphertext_len);
	if (e) {
		free_handle(&h);
		p = (char*)gcry_strerror(e);
		return debug_logerr(LLOG_ERROR, ERR_CIPHER, p);
	}

	free_handle(&h);

	return ERR_OK;
}

int decrypt(char *outdata, const char *ciphertext, size_t ciphertext_len, const char *key, const char *nonce) {
	char *p;
	int r;
	gcry_cipher_hd_t h;
	gcry_error_t e;

	r = create_handle(&h, key, nonce);
	if (r) {
		return debug_logerr(LLOG_ERROR, ERR_CIPHER, "decrypt handle (str)");
	}

	e = gcry_cipher_decrypt(h, outdata, ciphertext_len, ciphertext, ciphertext_len);
	if (e) {
		free_handle(&h);
		p = (char*)gcry_strerror(e);
		return debug_logerr(LLOG_ERROR, ERR_CIPHER, p);
	}

	free_handle(&h);

	return ERR_OK;
}


// DIGEST SECTION

/// Calculate a digest according to the specified algo.
static int calculate_digest_algo(const char *in, size_t in_len, char *out, enum gcry_md_algos algo) {
	gcry_error_t e;
	gcry_md_hd_t h;
	unsigned char *v;
	static unsigned int digest_len;

	if (algo == GCRY_MD_NONE) {
		algo = GCRY_MD_SHA512;
	}

	e = gcry_md_open(&h, algo, GCRY_MD_FLAG_SECURE);
	if (e) {
		return ERR_ENCODING;
	}
	e = gcry_md_enable(h, algo);
	if (e) {
		return ERR_COMPAT;
	}
	digest_len = gcry_md_get_algo_dlen(algo);

	gcry_md_write(h, in, in_len);
	v = gcry_md_read(h, 0);
	lq_cpy(out, v, digest_len);
	gcry_md_close(h);
	return ERR_OK;
}

/// Calculate digest using the default hashing algorithm (SHA256)
/// using the gcrypt library.
int lq_digest(const char *in, size_t in_len, char *out) {
	return calculate_digest_algo(in, in_len, out, GCRY_MD_NONE);
}


/// Apply public key to the gpg_store struct.
static int key_apply_public(struct gpg_store *gpg, gcry_sexp_t key) {
	char *p;
	size_t c;
	gcry_sexp_t pubkey;

	pubkey = gcry_sexp_find_token(key, "public-key", 10);
	if (pubkey == NULL) {
		return debug_logerr(LLOG_ERROR, ERR_KEYFAIL, "sexp pubkey");
	}
	pubkey = gcry_sexp_find_token(pubkey, "q", 1);
	if (pubkey == NULL) {
		return debug_logerr(LLOG_ERROR, ERR_KEYFAIL, "sexp q");
	}
	c = LQ_PUBKEY_LEN;
	p = (char*)gcry_sexp_nth_data(pubkey, 1, &c);
	if (p == NULL) {
		return debug_logerr(LLOG_ERROR, ERR_KEYFAIL, "sexp first data");
	}
	lq_cpy(gpg->public_key, p, LQ_PUBKEY_LEN);
	
	p = (char*)gcry_pk_get_keygrip(key, (unsigned char*)gpg->fingerprint);
	if (p == NULL) {
		return debug_logerr(LLOG_ERROR, ERR_KEYFAIL, "pubkey fingerprint");
	}

	return ERR_OK;
}

/// Create a new gcrypt keypair.
static int key_create(struct gpg_store *gpg) {
	int r;
	const char *p;
	const char *sexp_quick = "(genkey(ecc(flags eddsa)(curve Ed25519)))";
	gcry_sexp_t in;
	gcry_error_t e;

	// Set up parameters for key creation.
	e = gcry_sexp_new(&in, (const void*)sexp_quick, strlen(sexp_quick), 0);
	if (e) {
		p = gcry_strerror(e);
		return debug_logerr(LLOG_ERROR, ERR_KEYFAIL, (char*)p);
	}

	// Generate a new key with the given parameters.
	e = gcry_pk_genkey(&gpg->k, in);
	if (e) {
		p = gcry_strerror(e);
		return debug_logerr(LLOG_ERROR, ERR_KEYFAIL, (char*)p);
	}

	// Apply the public part of the key to the underlying key structure.
	r = key_apply_public(gpg, gpg->k);
	if (r) {
		return debug_logerr(LLOG_ERROR, ERR_KEYFAIL, "private create apply public");
	}

	return ERR_OK;
}

// Create a new store instance using the crypto partition path
// set in the configuration.
// Caller must free it.
LQStore *key_store_get() {
//	int r;
//	char *p;

//	r = lq_config_get(gpg_cfg_idx_dir, (void**)&p);
//	if (r) {
//		return NULL;
//	}
//	return lq_store_new(p);
	return gpg_key_store;
}

/**
 * \todo consistent endianness for key length in persistent storage (fwrite)
 * \todo doc must have enough in path for path + fingerprint hex
 *
 */
static int key_create_store(struct gpg_store *gpg, const char *passphrase, size_t passphrase_len) {
	char *p;
	int r;
	int kl;
	char v[LQ_CRYPTO_BUFLEN];
	int l;
	size_t c;
	size_t m;
	LQStore *store;
	LQPubKey *pubk;
	char nonce[CHACHA20_NONCE_LENGTH_BYTES];
	char buf_key[LQ_STORE_KEY_MAX];
	char buf_val[LQ_STORE_VAL_MAX];
	char ciphertext[LQ_CRYPTO_BUFLEN];
	char passphrase_hash[LQ_DIGEST_LEN];

	// Create the private key and corresponding public key.
	r = key_create(gpg);
	if (r) {
		return debug_logerr(LLOG_ERROR, ERR_KEYFAIL, "key create");
	}
	pubk = lq_publickey_new(gpg->public_key);
	if (pubk == NULL) {
		return debug_logerr(LLOG_ERROR, ERR_KEYFAIL, "publickey");
	}

	// Export the S-expression to a text buffer for saving, canonical formatting
	kl = gcry_sexp_sprint(gpg->k, GCRYSEXP_FMT_CANON, NULL, 0);
	m = (size_t)kl + 1;
	p = (char*)v + sizeof(int);
	c = 0;
	kl = gcry_sexp_sprint(gpg->k, GCRYSEXP_FMT_CANON, p, LQ_CRYPTO_BUFLEN - m);
	m -= (size_t)(kl + 1);
	c += kl;
	lq_cpy(v, &c, sizeof(int));

	// Pad the contents up to the blocksize boundary
	m = c;
	c = get_padsize(m, LQ_CRYPTO_BLOCKSIZE);

	// Hash the encryption key to the expected length.
	r = calculate_digest_algo(passphrase, passphrase_len, passphrase_hash, gpg_passphrase_digest);
	if (r) {
		return debug_logerr(LLOG_ERROR, ERR_DIGEST, "passphrase hash");
	}

	// Encrypt the payload with the passphrase and nonce.
	gcry_create_nonce(nonce, CHACHA20_NONCE_LENGTH_BYTES);
	r = encryptb(ciphertext, c, v, m+sizeof(int), passphrase_hash, nonce);
	if (r) {
		return debug_logerr(LLOG_ERROR, ERR_KEY_LOCK, "encrypt private key");
	}

	// Export the key (fingerprint) and value (ciphertext) to put in the store.
	// (We don't need the inner private key pointer anymore, so we re-use it.)
	lq_cpy(buf_val, nonce, CHACHA20_NONCE_LENGTH_BYTES);
	lq_cpy(buf_val + CHACHA20_NONCE_LENGTH_BYTES, ciphertext, c);
	gpg = (struct gpg_store*)pubk->impl;
	lq_cpy(buf_key, gpg->fingerprint, LQ_FP_LEN);

	// Instantiate the store.
	store = key_store_get();
	if (store == NULL) {
		return debug_logerr(LLOG_ERROR, ERR_KEYFILE, "create store");
	}

	// Write the ciphertext to the store.	
	l = c + CHACHA20_NONCE_LENGTH_BYTES;
	c = LQ_FP_LEN;
	r = store->put(LQ_CONTENT_KEY, store, buf_key, &c, buf_val, l);
	if (r) {
		return debug_logerr(LLOG_ERROR, ERR_KEYFILE, "put key in store");
	}

	// Check if a main key already exists in the store.
	// If not, set this one as main.
	*buf_key = gpg_default_store_key;
	c = LQ_STORE_VAL_MAX; 
	r = store->get(LQ_CONTENT_KEY, store, buf_key, 1, buf_val, &c);
	if (r) {
		if (r != ERR_NOENT) {
			debug(LLOG_ERROR, "crypto.gcrypt", "no default");
			return debug_logerr(LLOG_ERROR, ERR_KEYFILE, "default key");
		}
		c = 1;
		r = store->put(LQ_CONTENT_KEY, store, buf_key, &c, buf_val, l);
		if (r) {
			debug(LLOG_ERROR, "crypto.gcrypt", "fail put default");
			return debug_logerr(LLOG_ERROR, ERR_KEYFILE, "write default key");
		}
	}

	return ERR_OK;
}

/// Create a new keypair, encrypted with given passphrase.
static LQPrivKey* privatekey_alloc(const char *passphrase, size_t passphrase_len) {
	int r;
	LQPrivKey *o;
	struct gpg_store *gpg;

	// Allocate private key structures.
	o = lq_alloc(sizeof(LQPrivKey));
	if (o == NULL) {
		return NULL;
	}
	gpg = lq_alloc(sizeof(struct gpg_store));
	if (gpg == NULL) {
		lq_free(o);
		return NULL;
	}

	// Create the underlying private key.
	r = key_create_store(gpg, passphrase, passphrase_len);
	if (r) {
		lq_free(gpg);
		lq_free(o);
		return NULL;
	}

	// Populate the internal key structure.
	o->impl = (void*)gpg;
	o->key_typ = GPG_KEY_TYP;
	o->key_state = LQ_KEY_INIT;

	// No cleanup = caller must free it.
	debug_x(LLOG_INFO, "gpg", "created new private key", 1, MORGEL_TYP_BIN, LQ_FP_LEN, "fingerprint", gpg->fingerprint);

	return o;
}


/// Implements the interface to create a new private key.
LQPrivKey* lq_privatekey_new(const char *passphrase, size_t passphrase_len) {
	int r;
	LQPrivKey *o;
	if (passphrase == NULL) {
		return NULL;
	}

	o = privatekey_alloc(passphrase, passphrase_len);
	if (o == NULL) {
		return NULL;
	}
	r = lq_privatekey_lock(o, passphrase, passphrase_len);
	if (r) {
		return NULL;
	}
	return o;	
}

/// Parse data from buffer as S-expression text representing a key.
static int key_from_data(gcry_sexp_t *key, const char *indata, size_t indata_len) {
	gcry_error_t e;

	e = gcry_sexp_new(key, indata, indata_len, 0);
	if (e != GPG_ERR_NO_ERROR) {
		return debug_logerr(LLOG_ERROR, ERR_COMPAT, "not key data");
	}
	return ERR_OK;
}

/// Load a private key from the store's crypto partition.
static int key_from_store(struct gpg_store *gpg, const char *passphrase, size_t passphrase_len) {
	char *nonce;
	char *p;
	int r;
	LQStore *store;
	char inkey[LQ_FP_LEN];
	size_t inkey_len;
	char out[LQ_CRYPTO_BUFLEN];
	char in[LQ_CRYPTO_BUFLEN];
	size_t in_len;
	size_t out_len;
	char passphrase_hash[LQ_DIGEST_LEN];

	// Instantiate the store.
	store = key_store_get();

	// If a valid fingerprint is found in the gpg structure,
	// retrieve the key matching that fingerprint.
	// Otherwise, retrieve the main key.
	// Or fail if none of them can be found.
	inkey_len = LQ_FP_LEN;
	in_len = LQ_CRYPTO_BUFLEN;
	if (lq_cmp(gpg->fingerprint, gpg_fingerprint_zero, LQ_FP_LEN)) {
		lq_cpy(inkey, gpg->fingerprint, LQ_FP_LEN);	
	} else {
		*inkey = gpg_default_store_key;
		inkey_len = 1;
	}
	r = store->get(LQ_CONTENT_KEY, store, inkey, inkey_len, in, &in_len);
	if (r) {
		return ERR_NOENT;
	}

	// Hash the encryption key to the expected length.
	r = calculate_digest_algo(passphrase, passphrase_len, passphrase_hash, gpg_passphrase_digest);
	if (r) {
		return debug_logerr(LLOG_ERROR, ERR_DIGEST, "passphrase hash");
	}

	// Decrypt the private key data from the store
	// with the provided passphrase and the extracted nonce.
	nonce = in;
	p = (char*)in + CHACHA20_NONCE_LENGTH_BYTES;
	in_len -= CHACHA20_NONCE_LENGTH_BYTES;
	r = decryptb(out, p, in_len, passphrase_hash, nonce);
	if (r) {
		return ERR_KEY_UNLOCK;
	}

	// Attempt to parse and instantiate the key from the decrypted data.
	out_len = (size_t)(*((int*)out));
	p = (char*)(out+sizeof(int));
	r = key_from_data(&gpg->k, p, out_len);
	if (r) {
		return ERR_KEYFAIL;
	}

	return ERR_OK;
}

static int gpg_key_load(struct gpg_store *gpg, const char *passphrase, size_t passphrase_len, enum gpg_find_mode_e mode, const void *criteria) {
	int r;

	switch(mode) {
		case GPG_FIND_MAIN:
			r = key_from_store(gpg, passphrase, passphrase_len);
			if (r) {
				return debug_logerr(LLOG_WARNING, ERR_KEYFILE, "default key not found");
			}
			break;
		case GPG_FIND_ORCREATE:
			r = key_from_store(gpg, passphrase, passphrase_len);
			if (r == ERR_OK) {
				break;
			}
			// if no key could be loaded, attempt to create one.
			if (!lq_cmp(gpg_fingerprint_zero, gpg->fingerprint, LQ_FP_LEN)) {
				debug(LLOG_DEBUG, "gpg", "default private key not found, attempting create new");
				r = key_create_store(gpg, passphrase, passphrase_len);
				if (r) {
					return debug_logerr(LLOG_WARNING, ERR_KEYFILE, "create key when no default found");
				}
			}
			break;
		case GPG_FIND_FINGERPRINT:
			r = key_from_store(gpg, passphrase, passphrase_len);
			if (r) {
				return debug_logerr(LLOG_WARNING, ERR_KEYFILE, "fingerprint key not found");
			}
			break;
		default:
			return debug_logerr(LLOG_WARNING, ERR_FAIL, NULL);
	}

	r = key_apply_public(gpg, gpg->k);
	if (r) {
		return debug_logerr(LLOG_ERROR, ERR_KEYFAIL, "apply public key");
	}
	debug_x(LLOG_INFO, "gpg", "loaded private key", 1, MORGEL_TYP_BIN, LQ_FP_LEN, "fingerprint", gpg->fingerprint);
	
	return ERR_OK;
}


/// Implements the interface to load a private key from storage.
LQPrivKey* lq_privatekey_load(const char *passphrase, size_t passphrase_len, const char *fingerprint) {
	LQPrivKey *pk;
	enum gpg_find_mode_e m;
	struct gpg_store *gpg;
	int r;
	
	gpg = lq_alloc(sizeof(struct gpg_store));
	lq_zero(gpg, sizeof(struct gpg_store));
	m = GPG_FIND_ORCREATE;
	if (fingerprint != NULL) {
		lq_cpy(gpg->fingerprint, fingerprint, LQ_FP_LEN);
		m = GPG_FIND_FINGERPRINT;
	}
	r = gpg_key_load(gpg, passphrase, passphrase_len, m, NULL);
	if (r) {
		return NULL;	
	}
	pk = lq_alloc(sizeof(LQPrivKey));
	pk->key_typ = GPG_KEY_TYP;
	pk->key_state = LQ_KEY_INIT;
	pk->impl = gpg;

	return pk;
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
	return NULL;
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
		return ERR_KEYFAIL;
	}

	c = 0;
	err = gcry_mpi_scan(&sig_r, GCRYMPI_FMT_STD, sig->impl, LQ_POINT_LEN, &c);
	if (err != GPG_ERR_NO_ERROR) {
		return ERR_KEYFAIL;
	}
	if (c != 32) {
		return ERR_KEYFAIL;
	}

	c = 0;
	err = gcry_mpi_scan(&sig_s, GCRYMPI_FMT_STD, sig->impl + LQ_POINT_LEN, LQ_POINT_LEN, &c);
	if (err != GPG_ERR_NO_ERROR) {
		return ERR_KEYFAIL;
	}
	if (c != 32) {
		return ERR_KEYFAIL;
	}

	c = 0;
	err = gcry_sexp_build(&sigx, &c, "(sig-val(eddsa(r %m)(s %m)))", sig_r, sig_s);
	if (err != GPG_ERR_NO_ERROR) {
		return ERR_SIGFAIL;
	}

	r = calculate_digest_algo(data, data_len, digest, GCRY_MD_SHA512);
	if (r) {
		return ERR_DIGEST;
	}

	c = 0;
	err = gcry_sexp_build(&msgx, &c, "(data(flags eddsa)(hash-algo sha512)(value %b))", LQ_DIGEST_LEN, digest);
	if (err != GPG_ERR_NO_ERROR) {
		return ERR_DIGEST;
	}

	err = gcry_pk_verify(sigx, msgx, pubkey);
	if (err != GPG_ERR_NO_ERROR) {
		return ERR_SIGVALID;
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

size_t lq_publickey_fingerprint(LQPubKey* pubk, char **out) {
	struct gpg_store *gpg;

	gpg = (struct gpg_store*)pubk->impl;
	*out = gpg->fingerprint;
	return LQ_FP_LEN;
}

void lq_crypto_free() {
	lq_free((void*)gpg_key_store);
}

#endif
