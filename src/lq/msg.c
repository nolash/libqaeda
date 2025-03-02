#include <stddef.h>
#include <time.h>
#include <libtasn1.h>

#include "lq/msg.h"
#include "lq/mem.h"
#include "lq/crypto.h"
#include "lq/wire.h"
#include "endian.h"


LQMsg* lq_msg_new(const char *msg_data, size_t msg_len) {
	LQMsg *msg;

	msg = lq_alloc(sizeof(LQMsg));
	lq_set(msg, 0, sizeof(LQMsg));
	clock_gettime(CLOCK_REALTIME, &msg->time);

	return msg;
}

int lq_msg_sign(LQMsg *msg, LQPrivKey *pk) {
	return lq_msg_sign_salted(msg, pk, 0, 0);
}

int lq_msg_sign_salted(LQMsg *msg, LQPrivKey *pk, const char *salt, size_t salt_len) {
	int r;
	char *data;
	char digest[LQ_DIGEST_LEN];

	data = lq_alloc(msg->len);
	lq_cpy(data, msg->data, msg->len);
	msg->pubkey = lq_publickey_from_privatekey(pk);

	r = lq_digest(data, msg->len, (char*)digest);

	return r;
}

void lq_msg_free(LQMsg *msg) {
	if (msg->pubkey != 0) {
		lq_free(msg->pubkey);
	}
	lq_free(msg);
}

int lq_msg_serialize(LQMsg *msg, char *out, size_t *out_len) {
	int c;
	int r;
	char timedata[8];
	char err[1024];
	asn1_node node;

	r = asn1_array2tree(defs_asn1_tab, &node, err);
	if (r != ASN1_SUCCESS) {
		return 1;
	}

	c = (int)msg->len;
	r = asn1_write_value(node, "Qaeda.Msg.data", msg->data, c);
	if (r != ASN1_SUCCESS) {
		return 1;
	}

	lq_cpy(timedata, &msg->time.tv_sec, 4);
	lq_cpy(((char*)timedata)+4, &msg->time.tv_nsec, 4);
	r = to_endian(TO_ENDIAN_BIG, 4, timedata);
	if (r) {
		return 1;
	}
	r = to_endian(TO_ENDIAN_BIG, 4, ((char*)timedata)+4);
	if (r) {
		return 1;
	}

	c = sizeof(int);
	r = asn1_write_value(node, "Qaeda.Msg.timestamp", &timedata, c);
	if (r != ASN1_SUCCESS) {
		return 1;
	}

	c = msg->pubkey->lolen;
	r = asn1_write_value(node, "Qaeda.Msg.pubkey", &msg->pubkey->lokey, c);
	if (r != ASN1_SUCCESS) {
		return 1;
	}

	r = asn1_der_coding(node, "Qaeda.Msg", out, (int*)out_len, err);
	if (r != ASN1_SUCCESS) {
		return 1;
	}

	return 0;
}
