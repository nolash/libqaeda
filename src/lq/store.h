#ifndef LIBQAEDA_STORE_H_
#define  LIBQAEDA_STORE_H_

#include <stddef.h>

enum payload_e {
	LQ_CONTENT_RAW,
	LQ_CONTENT_MSG,
	LQ_CONTENT_CERT,	
	LQ_CONTENT_KEY,
};

typedef struct lq_store_t LQStore;
struct lq_store_t {
	int store_typ;
	void *userdata;
	int (*get)(enum payload_e typ, LQStore *store, const char *key, size_t key_len, char *value, size_t *value_len);
	int (*put)(enum payload_e typ, LQStore *store, const char *key, size_t *key_len, char *value, size_t value_len);
};


typedef struct lq_resolve_t LQResolve;
struct lq_resolve_t {
	LQStore *store;
	LQResolve *next;	
};

#endif // LIBQAEDA_STORE_H_
