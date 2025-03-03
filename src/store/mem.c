#include <hashmap.h>

#include "lq/mem.h"
#include "lq/store.h"
#include "lq/err.h"


static const int store_typ_mem = 2;

struct pair_t {
	const char *key;
	size_t key_len;
	const char *val;
	size_t val_len;
};

static int pair_cmp(const void *a, const void *b, void *userdata) {
	int i;
	int c;
	const char *pa;
	const char *pb;
	size_t l;

	lq_cpy(&l, userdata, sizeof(size_t));
	c = 0;
	for (i = 0; i < l; i++) {
		if (i % 8 == 0) {
			pa = a + c;
			pb = b + c;
			c++;
		}
		if (*pa == *pb) {
			continue;
		}
		if (*pa < *pb) {
			return -1;
		}
		return 1;
	}
	return 0;

}

static long unsigned int pair_hash(const void *item, long unsigned int s0, long unsigned int s1) {
	struct pair_t *o;

	o = (struct pair_t*)item;
	return (unsigned int)hashmap_sip(o->key, o->key_len, s0, s1);
}

void lq_mem_init(LQStore *store) {
	if (store->userdata == NULL) {
		store->userdata = (void*)hashmap_new(sizeof(struct pair_t) , 0, 0, 0, pair_hash, pair_cmp, NULL, NULL);
	}
}

int lq_mem_content_get(enum payload_e typ, LQStore *store, const char *key, size_t key_len, char *value, size_t *value_len) {
	lq_mem_init(store);
	return ERR_OK;
}

int lq_mem_content_put(enum payload_e typ, LQStore *store, const char *key, size_t *key_len, char *value, size_t value_len) {
	lq_mem_init(store);
	return ERR_OK;
}

struct lq_store_t LQMemContent = {
	.store_typ = store_typ_mem,
	.userdata = NULL,
	.get = lq_mem_content_get,	
	.put = lq_mem_content_put,
};
