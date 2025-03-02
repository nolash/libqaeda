#include <stddef.h>
#include <stdio.h>

#include "lq/store.h"
#include "hex.h"

static char buf[4096];

int lq_dummy_content_get(enum payload_e typ, const char *key, size_t key_len, char *value, size_t *value_len) {
	b2h((const unsigned char*)key, (int)key_len, (unsigned char*)buf);
	fprintf(stderr, "pretend get %d: %s\n", typ, buf);
	return 0;
}

int lq_dummy_content_put(enum payload_e typ, const char *key, size_t *key_len, char *value, size_t value_len) {
	b2h((const unsigned char*)key, (int)*key_len, (unsigned char*)buf);
	fprintf(stderr, "pretend put %d: %s -> %s\n", typ, buf, value);
	return 0;
}

struct lq_store_t LQDummyContent = {
	.get = lq_dummy_content_get,	
	.put = lq_dummy_content_put,
};
