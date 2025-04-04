#include <stddef.h>
#include <time.h>
#include <libtasn1.h>
#include <endian.h>
#include <llog.h>

#include "lq/msg.h"
#include "lq/mem.h"
#include "lq/err.h"
#include "lq/crypto.h"
#include "lq/wire.h"
#include "lq/store.h"
#include "debug.h"

static char zeros[LQ_PUBKEY_LEN];
static LQPubKey nokey = {
	.pk = NULL,
	.impl = zeros,
};

LQMsg* lq_msg_new(const char *msg_data, size_t msg_len) {
	LQMsg *msg;

	msg = lq_alloc(sizeof(LQMsg));
	lq_zero(msg, sizeof(LQMsg));
	clock_gettime(CLOCK_REALTIME, &msg->time);

	msg->data = lq_alloc(msg_len);
	lq_cpy(msg->data, msg_data, msg_len);
	msg->len = msg_len;

	return msg;
}

LQSig* lq_msg_sign(LQMsg *msg, LQPrivKey *pk, const char *salt) {
	return lq_msg_sign_extra(msg, pk, salt, NULL, 0);
}

static int msg_to_sign(LQMsg *msg, char *out, const char *extra, size_t extra_len) {
	int l;
	int r;
	char data[LQ_BLOCKSIZE];

	l = msg->len;
	if (extra_len > 0) {
		l += extra_len;
		lq_cpy(data, extra, extra_len);
	}
	lq_cpy(data + extra_len, msg->data, msg->len);

	return lq_digest(data, l, out);
}	

LQSig* lq_msg_sign_extra(LQMsg *msg, LQPrivKey *pk, const char *salt, const char *extra, size_t extra_len) {
	int r;
	char digest[LQ_DIGEST_LEN];
	LQSig *sig;

	if (extra == NULL) {
		extra_len = 0;
	}
	if (msg->pubkey == NULL) {
		msg->pubkey = lq_publickey_from_privatekey(pk);
		if (msg->pubkey == NULL) {
			debug_logerr(LLOG_DEBUG, ERR_NOKEY, "public key");
			return NULL;
		}
	}
	r = msg_to_sign(msg, digest, extra, extra_len);
	if (r) {
		debug_logerr(LLOG_DEBUG, r, "prepare message for sign");
		return NULL;
	}
	sig = lq_privatekey_sign(pk, digest, LQ_DIGEST_LEN, salt);
	if (sig == NULL) {
		debug_logerr(LLOG_DEBUG, r, "sign message");
		return NULL;
	}
	return sig;
}

int lq_msg_verify_extra(LQMsg *msg, LQSig *sig, const char *salt, const char *extra, size_t extra_len) {
	int r;
	char digest[LQ_DIGEST_LEN];
	LQMsg msg_valid;

	if (msg->pubkey == NULL) {
		return debug_logerr(LLOG_DEBUG, ERR_NONSENSE, "missing pubkey");
	}
	if (extra == NULL) {
		extra_len = 0;
	}
	r = msg_to_sign(msg, digest, extra, extra_len);
	if (r) {
		return debug_logerr(LLOG_DEBUG, r, "prepare message for verify");
	}
	r = lq_signature_verify(sig, digest, LQ_DIGEST_LEN);
	if (r) {
		return debug_logerr(LLOG_DEBUG, r, "verify message");
	}
	return ERR_OK;
}

void lq_msg_free(LQMsg *msg) {
	//if (msg->pubkey->pk = NULL) {
	if (msg->pubkey != NULL) {
		lq_publickey_free(msg->pubkey);
	}
	lq_free(msg->data);
	lq_free(msg);
}

int lq_msg_serialize(LQMsg *msg, char *out, size_t *out_len, LQResolve *resolve) {
	size_t c;
	int r;
	size_t mx;
	char tmp[LQ_DIGEST_LEN];
	char timedata[8];
	char err[1024];
	LQPubKey *pubkey;
	LQResolve *resolve_active;
	asn1_node node;
	char *keydata;

	mx = *out_len;
	*out_len = 0;
	lq_set(&node, 0, sizeof(node));
	r = asn1_array2tree(defs_asn1_tab, &node, err);
	if (r != ASN1_SUCCESS) {
		return ERR_INIT;
	}

	c = LQ_DIGEST_LEN;
	*out_len += c;
	if (*out_len > mx) {
		return ERR_OVERFLOW;
	}
	r = lq_digest(msg->data, msg->len, tmp);
	if (r != ERR_OK) {
		return r;
	}

	resolve_active = resolve;
	while (resolve_active != NULL) {
		r = resolve_active->store->put(LQ_CONTENT_MSG, resolve_active->store, tmp, &c, msg->data, msg->len);
		if (r != ERR_OK) {
			return r;
		}
		resolve_active = resolve_active->next;
	}

	r = asn1_write_value(node, "Qaeda.Msg.data", tmp, c);
	if (r != ASN1_SUCCESS) {
		return ERR_WRITE;
	}

	lq_cpy(timedata, &msg->time.tv_sec, 4);
	lq_cpy(((char*)timedata)+4, &msg->time.tv_nsec, 4);
	r = to_endian(TO_ENDIAN_BIG, 4, timedata);
	if (r) {
		return ERR_BYTEORDER;
	}
	r = to_endian(TO_ENDIAN_BIG, 4, ((char*)timedata)+4);
	if (r) {
		return ERR_BYTEORDER;
	}

	c = sizeof(int);
	*out_len += c;
	if (*out_len > mx) {
		return ERR_OVERFLOW;
	}
	r = asn1_write_value(node, "Qaeda.Msg.timestamp", &timedata, c);
	if (r != ASN1_SUCCESS) {
		return ERR_WRITE;
	}

	pubkey = msg->pubkey;
	if (pubkey == NULL) {
		pubkey = &nokey;
	}
	c = lq_publickey_bytes(pubkey, &keydata);
	*out_len += c;
	if (*out_len > mx) {
		return ERR_OVERFLOW;
	}
	r = asn1_write_value(node, "Qaeda.Msg.pubkey", keydata, c);
	if (r != ASN1_SUCCESS) {
		return ERR_WRITE;
	}

	*out_len = mx;
	r = asn1_der_coding(node, "Qaeda.Msg", out, (int*)out_len, err);
	if (r != ASN1_SUCCESS) {
		return ERR_ENCODING;
	}

	return ERR_OK;
}

int lq_msg_deserialize(LQMsg **msg, const char *in, size_t in_len, LQResolve *resolve) {
	int r;
	size_t c;
	char err[1024];
	char z[LQ_DIGEST_LEN];
	char tmp[1024];
	asn1_node node;
	asn1_node item;
	LQResolve *resolve_active;

	lq_zero(&node, sizeof(node));
	lq_zero(&item, sizeof(item));
	r = asn1_array2tree(defs_asn1_tab, &node, err);
	if (r != ASN1_SUCCESS) {
		return ERR_INIT;
	}

	r = asn1_create_element(node, "Qaeda.Msg", &item);
	if (r != ASN1_SUCCESS) {
		return ERR_READ;
	}

	r = asn1_der_decoding(&item, in, in_len, err);
	if (r != ASN1_SUCCESS) {
		return ERR_ENCODING;
	}

	c = LQ_DIGEST_LEN;
	r = asn1_read_value(item, "data", z, (int*)&c);
	if (r != ASN1_SUCCESS) {
		return ERR_READ;
	}
	c = 1024;
	resolve_active = resolve;
	while (resolve_active != NULL) {
		r = resolve_active->store->get(LQ_CONTENT_MSG, resolve_active->store, z, LQ_DIGEST_LEN, tmp, &c);
		if (r != ERR_OK) {
			return r;
		}
		resolve_active = resolve_active->next;
	}

	*msg = lq_msg_new((const char*)tmp, c);

	/// \todo document timestamp size
	c = 8;
	r = asn1_read_value(item, "timestamp", tmp, (int*)&c);
	if (r != ASN1_SUCCESS) {
		return ERR_READ;
	}
	if (is_le()) {
		flip_endian(4, (char*)tmp);
		flip_endian(4, ((char*)tmp)+4);
	}
	lq_cpy(&((*msg)->time.tv_sec), tmp, 4);
	lq_cpy(&((*msg)->time.tv_nsec), ((char*)tmp)+4, 4);

	c = 65;
	r = asn1_read_value(item, "pubkey", tmp, (int*)&c);
	if (r != ASN1_SUCCESS) {
		return ERR_READ;
	}

	return ERR_OK;
}
