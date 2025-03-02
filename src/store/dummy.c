#include <stddef.h>
#include <stdio.h>

#include "lq/store.h"
#include "lq/err.h"
#include "hex.h"

static const int store_typ_dummy = 1;

static char buf[4096];

int lq_dummy_content_get(enum payload_e typ, LQStore *store, const char *key, size_t key_len, char *value, size_t *value_len) {
	if (store_typ_dummy != store->store_typ) {
		return ERR_COMPAT;
	}
	b2h((const unsigned char*)key, (int)key_len, (unsigned char*)buf);
	fprintf(stderr, "pretend get %d: %s\n", typ, buf);
	return 0;
}

int lq_dummy_content_put(enum payload_e typ, LQStore *store, const char *key, size_t *key_len, char *value, size_t value_len) {
	if (store_typ_dummy != store->store_typ) {
		return ERR_COMPAT;
	}
	b2h((const unsigned char*)key, (int)*key_len, (unsigned char*)buf);
	fprintf(stderr, "pretend put %d: %s -> %s\n", typ, buf, value);
	return 0;
}

struct lq_store_t LQDummyContent = {
	.store_typ = store_typ_dummy,
	.userdata = NULL,
	.get = lq_dummy_content_get,	
	.put = lq_dummy_content_put,
};
