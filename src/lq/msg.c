#include <time.h>

#include "lq/msg.h"
#include "lq/mem.h"
#include "lq/crypto.h"


LQMsg* lq_msg_new(const char *msg_data, size_t msg_len) {
	LQMsg *msg;

	msg = lq_alloc(sizeof(LQMsg));
	lq_set(msg, 0, sizeof(LQMsg));
	msg->timestamp = (int)time(NULL);

	return msg;
}

void lq_msg_set_domain(LQMsg *msg, const char *domain) {
	lq_cpy(msg->domain, (void*)domain, LQ_MSG_DOMAIN_LEN);
}

int lq_msg_sign(LQMsg *msg, LQPrivKey *pk) {
	return lq_msg_sign_salted(msg, pk, 0, 0);
}

int lq_msg_sign_salted(LQMsg *msg, LQPrivKey *pk, const char *salt, size_t salt_len) {
	size_t l;
	int r;
	char *data;
	char digest[LQ_DIGEST_LEN];

	l = LQ_MSG_DOMAIN_LEN + msg->len;
	data = lq_alloc(l);
	lq_cpy(data, msg->domain, LQ_MSG_DOMAIN_LEN);
	lq_cpy(data + LQ_MSG_DOMAIN_LEN, msg->data, msg->len);
	msg->pubkey = lq_publickey_from_privatekey(pk);

	r = lq_digest(data, l, (char*)digest);
	msg->signature = lq_privatekey_sign(pk, msg->data, msg->len, salt, salt_len);

	return r;
}

void lq_msg_free(LQMsg *msg) {
	if (msg->pubkey != 0) {
		lq_free(msg->pubkey);
	}
	if (msg->signature != 0) {
		lq_free(msg->signature);
	}
	lq_free(msg);
}
