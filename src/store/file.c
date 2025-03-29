#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include <llog.h>
#include <hex.h>

#include "lq/crypto.h"
#include "lq/io.h"
#include "lq/store.h"
#include "lq/err.h"
#include "lq/mem.h"
#include "debug.h"

static const int store_typ_file = 3;

int lq_file_content_count(enum payload_e typ, LQStore *store, const char *key, size_t key_len) {
	int r;
	char **out;
	char pfx[1024];

	out = lq_alloc(sizeof(char**) * LQ_DIRS_MAX);
	pfx[0] = (char)typ + 0x30;
	lq_cpy(pfx+1, key, key_len);

	r = lq_files_pfx(store->userdata, out, LQ_DIRS_MAX, pfx, key_len + 1);

	lq_free(out);

	return r;
}

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
	sprintf(p, "/%s", buf);
	f = lq_open(path, O_RDONLY, S_IRUSR);
	if (f < 0) {
		return ERR_NOENT;
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
	sprintf(p, "/%s", buf);
	f = lq_open(path, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR);
	if (f < 0) {
		return ERR_NOENT;
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
	debug_x(LLOG_DEBUG, "store.file", "put file", 2, MORGEL_TYP_STR, 0, "path", path, MORGEL_TYP_NUM, 0, "bytes", c);
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
	.count = lq_file_content_count,
	.free = lq_file_content_free,
};

LQStore* lq_store_new(const char *spec) {
	int l;
	LQStore *store;

	l = strlen(spec) + 1;
	store = lq_alloc(sizeof(LQStore));
	lq_cpy(store, &LQFileContent, sizeof(LQFileContent));
	store->userdata = lq_alloc(l);
	lq_cpy(store->userdata, spec, l);
	return store;
}

void lq_store_free(LQStore *store) {
	lq_free(store->userdata);
	lq_free(store);
}

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
