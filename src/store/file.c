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
#include "lq/query.h"
#include "debug.h"

static const int store_typ_file = 3;

/// \todo key and val limits proper
int lq_file_content_count(enum payload_e typ, LQStore *store, const char *key, size_t key_len) {
	int r;
	char **out;
	char buf[LQ_STORE_KEY_MAX * 2 + 1];
	char pfx[1024];

	out = lq_alloc(sizeof(char**) * LQ_DIRS_MAX);
	pfx[0] = (char)typ + 0x30;
	b2h((const unsigned char*)key, (int)key_len, (unsigned char*)buf);
	lq_cpy(pfx+1, buf, strlen(buf));

	r = lq_files_pfx(store->userdata, out, LQ_DIRS_MAX, pfx, key_len + 1);

	lq_free(out);

	return r;
}

int lq_file_content_get(enum payload_e typ, LQStore *store, const char *key, size_t key_len, char *value, size_t *value_len) {
	int f;
	size_t l;
	size_t c;
	char buf[LQ_STORE_KEY_MAX * 2 + 1];
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
	sprintf(p, "%d%s", (char)typ, buf);
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

	debug_x(LLOG_DEBUG, "store.file", "get file", 2, MORGEL_TYP_STR, 0, "path", path, MORGEL_TYP_NUM, 0, "bytes", *value_len);

	return ERR_OK;

}

int lq_file_content_put(enum payload_e typ, LQStore *store, const char *key, size_t *key_len, char *value, size_t value_len) {
	size_t c;
	size_t l;
	char buf[LQ_STORE_KEY_MAX - 1];
	char path[1024];
	char *p;
	int f;

	if (*key_len > (LQ_STORE_KEY_MAX / 2) - 1) {
		return ERR_OVERFLOW;
	}
	if (store->store_typ != store_typ_file) {
		return ERR_COMPAT;
	}
	p = (char*)store->userdata;
	lq_cpy(path, p, strlen(p) + 1);
	p = path + strlen(path);
	b2h((const unsigned char*)key, (int)*key_len, (unsigned char*)buf);
	sprintf(p, "%d%s", (char)typ, (unsigned char*)buf);
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
	lq_free(store->userdata);
	lq_free(store);
}

/**
 * \todo DRY with lq_files_pfx
 * \todo prefix mismatches leak?
 */
static int query_list(const char *path, char **files, size_t files_len, const char *prefix, char prefix_len) {
	int r;
	int i;
	int c;
	size_t l;

	c = 0;
	r = lq_files(path, files, files_len);
	for (i = 0; i < r; i++) {
		l = strlen(*(files+i));
		if (l < prefix_len) {
			lq_free(*(files+i));
		}
		if (!lq_cmp(prefix, *(files+i), prefix_len)) {
	//		lq_free(*(files+c));// attempt at stopping mismatch leak.
			*(files+c) = *(files+i);
			c++;
		}
	}
	return c;
}

/// \todo  DRY with lq_file_count
LQQuery* lq_query_new(enum payload_e typ, LQStore *store, const char *key, size_t key_len) {
	LQQuery *query;
	//char **out;
	char buf[LQ_STORE_KEY_MAX * 2 + 1];
	char pfx[1024];

	query = lq_alloc(sizeof(LQQuery));
	lq_zero(query, sizeof(LQQuery));
	query->files = lq_alloc(sizeof(char**) * LQ_DIRS_MAX);
	pfx[0] = (char)typ + 0x30;
	b2h((const unsigned char*)key, (int)key_len, (unsigned char*)buf);
	lq_cpy(pfx+1, buf, strlen(buf) + 1);

	key_len *= 2;
	query->typ = typ;
	query->files_len = query_list(store->userdata, query->files, LQ_DIRS_MAX, pfx, key_len + 1);
	if (query->files_len == 0) {
		return NULL;
	}
	query->value = lq_alloc(LQ_STORE_VAL_MAX);
	query->key = lq_alloc(LQ_STORE_KEY_MAX);
	query->store = store;
	query->state = LQ_QUERY_READY;

	debug_x(LLOG_DEBUG, "store.file", "query", 2, MORGEL_TYP_STR, 0, "pfx", key, MORGEL_TYP_NUM, 0, "typ", (int)typ);

	return query;
}

int lq_query_next(LQQuery *query) {
	int r;
	char *p;
	//char b[LQ_STORE_KEY_MAX];

	if (query->state & LQ_QUERY_EOF) {
		return ERR_EOF;	
	}
	p = *(query->files + query->files_cur) + 1;
	query->key_len = h2b(p, (char*)query->key);
	if (query->key_len == 0) {
		query->state = LQ_QUERY_GONER;
		return ERR_ENCODING;
	}
	query->value_len = LQ_STORE_VAL_MAX;
	r = query->store->get(query->typ, query->store, query->key, query->key_len, query->value, &query->value_len);
	if (r != ERR_OK) {
		query->value_len = 0;
		query->state = LQ_QUERY_GONER;
		return ERR_FAIL;
	}
	if (++query->files_cur == query->files_len) {
		query->state |= LQ_QUERY_EOF;
	}
	return ERR_OK;
}

int lq_query_get_val_len(LQQuery *query) {
	if (!(query->state & LQ_QUERY_READY)) {
		return -1;
	}
	return query->value_len;
}

char* lq_query_get_val(LQQuery *query) {
	if (!(query->state & LQ_QUERY_READY)) {
		return NULL;
	}
	return query->value;
}

int lq_query_get_key_len(LQQuery *query) {
	if (!(query->state & LQ_QUERY_READY)) {
		return -1;
	}
	return query->key_len;
}

char* lq_query_get_key(LQQuery *query) {
	if (!(query->state & LQ_QUERY_READY)) {
		return NULL;
	}
	return query->key;
}

void lq_query_free(LQQuery *query) {
	char *p;
	int i;

	i = 0;
	while(1) {
		if (*((query->files)+i) != NULL) {
			break;
		}
		lq_free(*((query->files)+i));
		*((query->files)+i) = NULL;
		i++;
	}
	lq_free(query->files);
	lq_free(query->key);
	lq_free(query->value);
	lq_free(query);
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
