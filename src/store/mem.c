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
	struct pair_t *pa;
	struct pair_t *pb;
	const char *ka;
	const char *kb;

	pa = (struct pair_t*)a;
	pb = (struct pair_t*)b;
	ka = pa->key;
	kb = pb->key;
	for (i = 0; i < pa->key_len; i++) {
		if (*ka == *kb) {
			ka++;
			kb++;
			continue;
		}
		if (*ka < *kb) {
			return -1;
		}
		return 1;
	}
	return 0;

}

static long unsigned int pair_hash(const void *item, long unsigned int s0, long unsigned int s1) {
	unsigned int r;
	struct pair_t *o;

	o = (struct pair_t*)item;
	r = (unsigned int)hashmap_sip(o->key, o->key_len, s0, s1);
	return r;
}

struct hashmap* lq_mem_init(LQStore *store) {
	if (store->userdata == NULL) {
		store->userdata = (void*)hashmap_new(sizeof(struct pair_t) , 0, 0, 0, pair_hash, pair_cmp, NULL, NULL);
	}
	return (struct hashmap *)store->userdata;
}

int lq_mem_content_get(enum payload_e typ, LQStore *store, const char *key, size_t key_len, char *value, size_t *value_len) {
	struct hashmap *o;
	struct pair_t v;
	const struct pair_t *p;
	
	o = lq_mem_init(store);

	v.key = key;
	v.key_len = key_len;

	p = hashmap_get(o, &v);
	if (p == NULL) {
		return ERR_NOENT;
	}
	*value_len = p->val_len;
	lq_cpy(value, p->val, *value_len);
	
	return ERR_OK;
}

int lq_mem_content_put(enum payload_e typ, LQStore *store, const char *key, size_t *key_len, char *value, size_t value_len) {
	struct hashmap *o;
	struct pair_t v;

	v.key = key;
	v.key_len = *key_len;
	v.val = value;
	v.val_len = value_len;

	o = lq_mem_init(store);
	hashmap_set(o, &v);
	return ERR_OK;
}

void lq_mem_content_free(LQStore *store) {
	if (store->userdata != NULL) {
		hashmap_free((struct hashmap*)store->userdata);
		store->userdata = NULL;
	}
}

struct lq_store_t LQMemContent = {
	.store_typ = store_typ_mem,
	.userdata = NULL,
	.get = lq_mem_content_get,	
	.put = lq_mem_content_put,
	.free = lq_mem_content_free,
};

LQStore* lq_store_new(const char *spec) {
	LQStore *store;

	store = lq_alloc(sizeof(LQStore));
	lq_cpy(store, &LQMemContent, sizeof(LQMemContent));
	return store;
}

void lq_store_free(LQStore *store) {
	lq_free(store);
}
