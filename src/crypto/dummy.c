#include "lq/crypto.h"
#include "lq/mem.h"

// sha256sum "foo" 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
static const char pubkey_dummy_transform[32] = {
	0x2c, 0x26, 0xb4, 0x6b, 0x68, 0xff, 0xc6, 0x8f,
	0xf9, 0x9b, 0x45, 0x3c, 0x1d, 0x30, 0x41, 0x34,
	0x13, 0x42, 0x2d, 0x70, 0x64, 0x83, 0xbf, 0xa0,
	0xf9, 0x8a, 0x5e, 0x88, 0x62, 0x66, 0xe7, 0xae
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

LQPrivKey* lq_privatekey_new(char *seed, size_t seed_len) {
	LQPrivKey *pk;

	pk = lq_alloc(sizeof(LQPrivKey));
	pk->lokey = lq_alloc(seed_len);
	lq_cpy(pk->lokey, seed, seed_len);
	pk->lolen = seed_len;
	return pk;
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
	int i;
	char *src;
	char *dst;
	LQPubKey *pubk;

	pubk = lq_alloc(sizeof(LQPubKey));
	pubk->pk = pk;
	pubk->lokey = lq_alloc(pk->lolen);
	pubk->lolen = pk->lolen;
	lq_cpy(pubk->lokey, pk->lokey, pk->lolen);
	for (i = 0; i < pubk->lolen; i++) {
		src = pk->lokey + i;
		*src ^= *(pubkey_dummy_transform + i);
		dst = pubk->lokey + i;
		*dst = *src;
	}

	return pubk;
}

LQSig* lq_privatekey_sign(LQPrivKey *pk, const char *msg, size_t msg_len, const char *salt, size_t salt_len) {
	int i;
	const char *src;
	char *dst;
	LQSig *sig;

	if (msg_len != 32) {
		return NULL;
	}
	if (salt_len != 32) {
		return NULL;
	}

	sig = lq_alloc(sizeof(LQSig));
	sig->pubkey = lq_publickey_from_privatekey(pk);
	sig->lolen = msg_len * 2 + 1;
	sig->losig = lq_alloc(sig->lolen);

	for (i = 0; i < msg_len; i++) {
		src = msg + i;
		dst = sig->losig + i;
		*dst = *src ^ sig_dummy_transform[i];
		*dst ^= *(salt + i);

		src += msg_len;
		dst += msg_len;
		*dst = *src ^ sig_dummy_transform[i + msg_len];
		*dst ^= *(salt + i);
	}
	*((char*)sig->losig + sig->lolen) = 0x2a;

	return sig;
}

void lq_privatekey_free(LQPrivKey *pk) {
	lq_free(pk->lokey);
	lq_free(pk);
}

void lq_publickey_free(LQPubKey *pubk) {
	lq_free(pubk->lokey);
	lq_free(pubk);
}

void lq_signature_free(LQSig *sig) {
	lq_free(sig->losig);		
	lq_free(sig);
}
