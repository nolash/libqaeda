#ifndef LIBQAEDA_STORE_H_
#define  LIBQAEDA_STORE_H_

#include <stddef.h>

enum payload_e {
	LQ_CONTENT_RAW,
	LQ_CONTENT_MSG,
	LQ_CONTENT_CERT,	
	LQ_CONTENT_KEY,
};

struct lq_store_t {
	int (*get)(enum payload_e typ, const char *key, size_t key_len, char *value, size_t *value_len);
	int (*put)(enum payload_e typ, const char *key, size_t *key_len, char *value, size_t value_len);
};


typedef struct lq_resolve_t LQResolve;
struct lq_resolve_t {
	struct lq_store_t *store;
	LQResolve *next;	
};

#endif // LIBQAEDA_STORE_H_
