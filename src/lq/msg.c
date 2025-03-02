#include <stddef.h>
#include <time.h>
#include <libtasn1.h>

#include "lq/msg.h"
#include "lq/mem.h"
#include "lq/err.h"
#include "lq/crypto.h"
#include "lq/wire.h"
#include "endian.h"

static LQPubKey nokey = {
	.pk = 0,
	.lokey = "",
	.lolen = 0,
};

static char nosalt[LQ_SALT_LEN];

LQMsg* lq_msg_new(const char *msg_data, size_t msg_len) {
	LQMsg *msg;

	msg = lq_alloc(sizeof(LQMsg));
	lq_set(msg, 0, sizeof(LQMsg));
	clock_gettime(CLOCK_REALTIME, &msg->time);

	msg->data = lq_alloc(msg_len);
	lq_cpy(msg->data, msg_data, msg_len);
	msg->len = msg_len;

	return msg;
}

LQSig* lq_msg_sign(LQMsg *msg, LQPrivKey *pk) {
	return lq_msg_sign_salted(msg, pk, nosalt, LQ_SALT_LEN);
}

LQSig* lq_msg_sign_salted(LQMsg *msg, LQPrivKey *pk, const char *salt, size_t salt_len) {
	int r;
	char *data;
	char digest[LQ_DIGEST_LEN];
	LQSig *sig;

	data = lq_alloc(msg->len);
	lq_cpy(data, msg->data, msg->len);
	msg->pubkey = lq_publickey_from_privatekey(pk);

	r = lq_digest(data, msg->len, (char*)digest);
	if (r != ERR_OK) {
		return NULL;
	}
	sig = lq_privatekey_sign(pk, digest, LQ_DIGEST_LEN, salt, salt_len);

	return sig;
}

void lq_msg_free(LQMsg *msg) {
	if (msg->pubkey != 0) {
		lq_free(msg->pubkey);
	}
	lq_free(msg->data);
	lq_free(msg);
}

int lq_msg_serialize(LQMsg *msg, char *out, size_t *out_len) {
	int c;
	int r;
	size_t mx;
	char timedata[8];
	char err[1024];
	LQPubKey *pubkey;
	asn1_node node;

	mx = *out_len;
	*out_len = 0;
	lq_set(&node, 0, sizeof(node));
	r = asn1_array2tree(defs_asn1_tab, &node, err);
	if (r != ASN1_SUCCESS) {
		return ERR_INIT;
	}

	c = (int)msg->len;
	*out_len += c;
	if (*out_len > mx) {
		return ERR_OVERFLOW;
	}
	r = asn1_write_value(node, "Qaeda.Msg.data", msg->data, c);
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
	c = pubkey->lolen;
	*out_len += c;
	if (*out_len > mx) {
		return ERR_OVERFLOW;
	}
	r = asn1_write_value(node, "Qaeda.Msg.pubkey", pubkey->lokey, c);
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

int lq_msg_deserialize(LQMsg **msg, const char *in, size_t in_len) {
	int r;
	int c;
	char err[1024];
	char tmp[1024];
	asn1_node node;
	asn1_node item;

	lq_set(&node, 0, sizeof(node));
	lq_set(&item, 0, sizeof(item));
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

	// \todo buffered read
	// \todo avoid double alloc for msg data
	c = 1024;
	r = asn1_read_value(item, "data", tmp, &c);
	if (r != ASN1_SUCCESS) {
		return ERR_READ;
	}
	*msg = lq_msg_new((const char*)tmp, (size_t)c);

	/// \todo document timestamp size
	c = 8;
	r = asn1_read_value(item, "timestamp", tmp, &c);
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
	r = asn1_read_value(item, "pubkey", tmp, &c);
	if (r != ASN1_SUCCESS) {
		return ERR_READ;
	}

	return ERR_OK;
}
