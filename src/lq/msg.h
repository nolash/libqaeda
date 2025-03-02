#ifndef LIBQAEDA_MSG_H_
#define LIBQAEDA_MSG_H_

#include <stddef.h>
#include <time.h>

#include "lq/crypto.h"

#ifndef LQ_MSG_DOMAIN_LEN
#define LQ_MSG_DOMAIN_LEN 8
#endif

struct lq_msg_t {
	char *data;
	size_t len;
	struct timespec time;
	LQPubKey *pubkey;
};
typedef struct lq_msg_t LQMsg;

LQMsg* lq_msg_new(const char *msg_data, size_t msg_len);
int lq_msg_sign(LQMsg *msg, LQPrivKey *pk);
int lq_msg_sign_salted(LQMsg *msg, LQPrivKey *pk, const char *salt, size_t salt_len);
int lq_msg_serialize(LQMsg *msg, char *out, size_t *out_len);
int lq_msg_deserialize(LQMsg **msg, const char *in, size_t in_len);
void lq_msg_free(LQMsg *msg);
#endif // LIBQAEDA_MSG_H_
