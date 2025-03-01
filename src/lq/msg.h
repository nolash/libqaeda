#ifndef LIBQAEDA_MSG_H_
#define LIBQAEDA_MSG_H_

#include <stddef.h>

#include "lq/crypto.h"

struct lq_msg_t {
	const char *msg_data;
	size_t msg_len;
	const char *msg_domain;
	size_t *msg_domain_len;
	int msg_timestamp;
	struct LQPubKey *msg_pubkey;
	struct LQSig *msg_signature;
};
typedef struct lq_msg_t LQMsg;

#endif // LIBQAEDA_MSG_H_

