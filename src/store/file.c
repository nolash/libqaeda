#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include "lq/crypto.h"
#include "lq/io.h"
#include "lq/store.h"
#include "lq/err.h"
#include "lq/mem.h"
#include "hex.h"

static const int store_typ_file = 3;

int lq_file_content_get(enum payload_e typ, LQStore *store, const char *key, size_t key_len, char *value, size_t *value_len) {
	int f;
	int r;
	size_t l;
	size_t c;
	char buf[LQ_DIGEST_LEN * 2 + 1];
	char path[1024];
	char *p;

	if (store->store_typ != store_typ_file) {
		return ERR_COMPAT;
	}

	// \todo dry
	p = (char*)store->userdata;
	lq_cpy(path, p, strlen(p) + 1);
	p = path + strlen(path);
	b2h((const unsigned char*)key, (int)key_len, (unsigned char*)buf);
	r = sprintf(p, "/%s", buf);

	if (r < 0) {
		return ERR_READ;
	}
	f = lq_open(path, O_RDONLY, S_IRUSR);
	if (f < 0) {
		return ERR_READ;
	}

	p = value;
	l = 0;
	while (1) {
		c = lq_read(f, p, *value_len - l);
		if (c == 0) {
			break;
		}
		l += c;
		if (l > *value_len) {
			lq_close(f);
			return ERR_OVERFLOW;
		}
		p += c;	
	}
	lq_close(f);

	*value_len = l;

	return ERR_OK;

}

int lq_file_content_put(enum payload_e typ, LQStore *store, const char *key, size_t *key_len, char *value, size_t value_len) {
	int r;
	size_t c;
	size_t l;
	char buf[LQ_DIGEST_LEN * 2 + 1];
	char path[1024];
	char *p;
	int f;

	if (store->store_typ != store_typ_file) {
		return ERR_COMPAT;
	}
	p = (char*)store->userdata;
	lq_cpy(path, p, strlen(p) + 1);
	p = path + strlen(path);
	b2h((const unsigned char*)key, (int)*key_len, (unsigned char*)buf);
	r = sprintf(p, "/%s", buf);
	if (r < 0) {
		return ERR_WRITE;
	}
	f = lq_open(path, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR);
	if (f < 0) {
		return ERR_WRITE;
	}
	l = value_len;
	p = value;
	while (l > 0) {
		c = write(f, p, l);
		if (c < 0) {
			lq_close(f);
			return ERR_WRITE;
		}
		if (c == 0) {
			break;
		}
		l -= c;
		p += c;
	}
	lq_close(f);
	return ERR_OK;
}

void lq_file_content_free(LQStore *store) {
}

struct lq_store_t LQFileContent = {
	.store_typ = store_typ_file,
	.userdata = "",
	.get = lq_file_content_get,	
	.put = lq_file_content_put,
	.free = lq_file_content_free,
};

//LQStore* lq_file_content_new(const char *dir) {
//	char path[1024];
//	LQStore *store;
//
//	store = lq_alloc(sizeof(LQStore));
//	if (store == NULL) {
//		return NULL;
//	}
//	store->get = lq_file_content_get;
//	store->put = lq_file_content_put;
//
//	return store;
//}
//
//void lq_file_content_free(LQStore *store) {
//	lq_free(store->userdata);
//}
