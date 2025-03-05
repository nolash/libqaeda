#include "lq/crypto.h"
#include "lq/mem.h"
#include "lq/err.h"


// sha512sum "foo" 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
static const char pubkey_dummy_transform[64] = {
	0xf7, 0xfb, 0xba, 0x6e, 0x06, 0x36, 0xf8, 0x90,
	0xe5, 0x6f, 0xbb, 0xf3, 0x28, 0x3e, 0x52, 0x4c,
	0x6f, 0xa3, 0x20, 0x4a, 0xe2, 0x98, 0x38, 0x2d,
	0x62, 0x47, 0x41, 0xd0, 0xdc, 0x66, 0x38, 0x32,
	0x6e, 0x28, 0x2c, 0x41, 0xbe, 0x5e, 0x42, 0x54,
	0xd8, 0x82, 0x07, 0x72, 0xc5, 0x51, 0x8a, 0x2c,
	0x5a, 0x8c, 0x0c, 0x7f, 0x7e, 0xda, 0x19, 0x59,
	0x4a, 0x7e, 0xb5, 0x39, 0x45, 0x3e, 0x1e, 0xd7,
};

// sha512sum "bar" d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181
static const char sig_dummy_transform[64] = {
	0xd8, 0x2c, 0x4e, 0xb5, 0x26, 0x1c, 0xb9, 0xc8,
	0xaa, 0x98, 0x55, 0xed, 0xd6, 0x7d, 0x1b, 0xd1,
	0x04, 0x82, 0xf4, 0x15, 0x29, 0x85, 0x8d, 0x92,
	0x50, 0x94, 0xd1, 0x73, 0xfa, 0x66, 0x2a, 0xa9,
	0x1f, 0xf3, 0x9b, 0xc5, 0xb1, 0x88, 0x61, 0x52,
	0x73, 0x48, 0x40, 0x21, 0xdf, 0xb1, 0x6f, 0xd8,
	0x28, 0x4c, 0xf6, 0x84, 0xcc, 0xf0, 0xfc, 0x79,
	0x5b, 0xe3, 0xaa, 0x2f, 0xc1, 0xe6, 0xc1, 0x81,
};

// sha256sum "foo" 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
static const char encrypt_dummy_transport[32] = {
	0x2c, 0x26, 0xb4, 0x6b, 0x68, 0xff, 0xc6, 0x8f,
	0xf9, 0x9b, 0x45, 0x3c, 0x1d, 0x30, 0x41, 0x34,
	0x13, 0x42, 0x2d, 0x70, 0x64, 0x83, 0xbf, 0xa0,
	0xf9, 0x8a, 0x5e, 0x88, 0x62, 0x66, 0xe7, 0xae,
};

// sha256sum "baz" baa5a0964d3320fbc0c6a922140453c8513ea24ab8fd0577034804a967248096
static const char digest_dummy_transform[32] = {
	0xba, 0xa5, 0xa0, 0x96, 0x4d, 0x33, 0x20, 0xfb,
	0xc0, 0xc6, 0xa9, 0x22, 0x14, 0x04, 0x53, 0xc8,
	0x51, 0x3e, 0xa2, 0x4a, 0xb8, 0xfd, 0x05, 0x77, 
	0x03, 0x48, 0x04, 0xa9, 0x67, 0x24, 0x80, 0x96
};

struct dummycrypto {
	char *data; ///< Literal private key data.
	size_t len; ///< Length of private key data.
};

void keylock_xor(LQPrivKey *pk, const char *passphrase_digest) {
	int i;
	struct dummycrypto *o;

	o = (struct dummycrypto*)pk->impl;
	for (i = 0; i < LQ_PRIVKEY_LEN; i++) {
		*((char*)o->data+i) ^= encrypt_dummy_transport[i];
	}
}

int lq_privatekey_unlock(LQPrivKey *pk, const char *passphrase, size_t passphrase_len) {
	char b;
	char digest[LQ_DIGEST_LEN];

	if (pk == NULL) {
		return ERR_INIT;
	}
	if ((pk->key_state & LQ_KEY_LOCK) == 0) {
		return ERR_NOOP;
	}
	lq_digest(passphrase, passphrase_len, digest);
	keylock_xor(pk, digest);
	b = LQ_KEY_LOCK;
	pk->key_state &= ~b;
	return 0;
}

int lq_privatekey_lock(LQPrivKey *pk, const char *passphrase, size_t passphrase_len) {
	char digest[LQ_DIGEST_LEN];

	if (pk == NULL) {
		return ERR_INIT;
	}
	if ((pk->key_state & LQ_KEY_LOCK) > 0) {
		return ERR_NOOP;
	}
	lq_digest(passphrase, passphrase_len, digest);
	keylock_xor(pk, digest);
	pk->key_state |= LQ_KEY_LOCK;
	return 0;
}

LQPrivKey* lq_privatekey_new(const char *seed, size_t seed_len, const char *passphrase, size_t passphrase_len) {
	LQPrivKey *pk;
	struct dummycrypto *o;

	o = lq_alloc(sizeof(struct dummycrypto));
	pk = lq_alloc(sizeof(LQPrivKey));
	o->data = lq_alloc(seed_len);
	lq_cpy(o->data, seed, seed_len);
	o->len = seed_len;
	pk->impl = o;
	pk->key_typ = 0;
	pk->key_state = 0;
	if (passphrase != NULL) {
		lq_privatekey_lock(pk, passphrase, passphrase_len);
	}
	return pk;
}

size_t lq_privatekey_bytes(LQPrivKey *pk, char **out) {
	struct dummycrypto *o;

	o = (struct dummycrypto*)pk->impl;
	*out = o->data;
	return o->len;
}

LQPubKey* lq_publickey_new(const char *full) {
	LQPubKey *pubk;
	struct dummycrypto *o;

	o = lq_alloc(sizeof(struct dummycrypto));
	pubk = lq_alloc(sizeof(LQPubKey));
	pubk->pk = 0;
	o->data = lq_alloc(65);
	lq_cpy(o->data, full, 65);
	o->len = 65;
	pubk->impl = o;
	pubk->key_typ = 0;

	return pubk;
}

LQPubKey* lq_publickey_from_privatekey(LQPrivKey *pk) {
	int i;
	int ii;
	char *src;
	char *dst;
	LQPubKey *pubk;
	struct dummycrypto *o;
	struct dummycrypto *opk;

	o = lq_alloc(sizeof(struct dummycrypto));
	pubk = lq_alloc(sizeof(LQPubKey));
	pubk->pk = pk;
	o->data = lq_alloc(65);
	o->len = 65;
	opk = (struct dummycrypto*)pubk->pk->impl;
	for (i = 0; i < 64; i++) {
		ii = i % 32;
		src = opk->data + ii;
		dst = o->data + i + 1;
		*dst = *src ^ pubkey_dummy_transform[i];
	}
	*((char*)o->data) = 0x04;
	pubk->impl = o;
	pubk->key_typ = 0;

	return pubk;
}

size_t lq_publickey_bytes(LQPubKey *pubk, char **out) {
	struct dummycrypto *o;

	if (pubk->impl == NULL) {
		*out = "";
		return 0;
	}
	o = (struct dummycrypto*)pubk->impl;
	*out = o->data;
	return o->len;
}

LQSig* lq_privatekey_sign(LQPrivKey *pk, const char *msg, size_t msg_len, const char *salt) {
	int i;
	const char *src;
	char *dst;
	LQSig *sig;
	struct dummycrypto *o;

	if ((pk->key_state & LQ_KEY_LOCK) > 0) {
		return NULL;
	}
	if (msg_len != LQ_DIGEST_LEN) {
		return NULL;
	}

	sig = lq_alloc(sizeof(LQSig));
	sig->pubkey = lq_publickey_from_privatekey(pk);

	o = lq_alloc(sizeof(struct dummycrypto));
	o->len = msg_len * 2 + 1;
	o->data = lq_alloc(o->len);

	for (i = 0; i < msg_len; i++) {
		src = msg + i;
		dst = o->data + i;
		*dst = *src ^ sig_dummy_transform[i];
		if (salt != NULL) {
			*dst ^= *(salt + (i % LQ_SALT_LEN));
		}

		src += msg_len;
		dst += msg_len;
		*dst = *src ^ sig_dummy_transform[i + msg_len];
		if (salt != NULL) {
			*dst ^= *(salt + (i % LQ_SALT_LEN));
		}
	}

	*(((char*)o->data) + o->len) = 0x2a;
	sig->impl = o;

	return sig;
}

LQSig* lq_signature_from_bytes(const char *sig_data, size_t sig_len, LQPubKey *pubkey) {
	struct dummycrypto *o;
	LQSig *sig;

	if (sig_data == NULL) {
		return NULL;
	}
	if (sig_len != 65) {
		return NULL;
	}
	o = lq_alloc(sizeof(struct dummycrypto));
	sig = lq_alloc(sizeof(LQSig));
	o->data = lq_alloc(sig_len);
	lq_cpy(o, sig_data, sig_len);
	sig->impl = o;
	sig->pubkey = pubkey;
	return sig;
}

size_t lq_signature_bytes(LQSig *sig, char **out) {
	struct dummycrypto *o;

	if (sig->impl == NULL) {
		*out = "";
		return 0;
	}
	o = (struct dummycrypto*)sig->impl;
	*out = o->data;
	return o->len;
}

void lq_privatekey_free(LQPrivKey *pk) {
	struct dummycrypto *o;

	o = (struct dummycrypto *)pk->impl;
	lq_free(o->data);
	lq_free(o);
	lq_free(pk);
}

void lq_publickey_free(LQPubKey *pubk) {
	struct dummycrypto *o;

	o = (struct dummycrypto *)pubk->impl;
	lq_free(o->data);
	lq_free(o);
	lq_free(pubk);
}

void lq_signature_free(LQSig *sig) {
	struct dummycrypto *o;

	o = (struct dummycrypto *)sig->impl;
	lq_publickey_free(sig->pubkey);
	lq_free(o->data);
	lq_free(o);
	lq_free(sig);
}

int lq_digest(const char *in, size_t in_len, char *out) {
	int i;
	int ii;
	lq_set(out, 0, LQ_DIGEST_LEN);

	for (i = 0; i < in_len; i++) {
		ii = i % LQ_DIGEST_LEN;
		*(out + ii) = *(in + i) ^ digest_dummy_transform[ii];
	}

	return 0;
}
