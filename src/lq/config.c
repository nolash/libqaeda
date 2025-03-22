#include <string.h>

#include "lq/err.h"
#include "lq/mem.h"
#include "lq/config.h"

static const int config_core_typs[] = {
	LQ_TYP_STR,
	LQ_TYP_STR,
	LQ_TYP_STR,
	LQ_TYP_STR,
};

static const char *config_core_name[] = {
	"BASEDIR",
	"CONFIGDIR",
	"DATADIR",
	"CACHEDIR",
};

static char **config_idx;

static struct config_t {
	void *mem; ///< Config data memory.
	void **members; ///< Member pointer.
	enum lq_typ_e *typs; ///< Member type.
	size_t last; ///< Last registered members index.
	size_t cap; ///< Bytes allocated for config content.
	size_t len; ///< Bytes currently used for content.
} config;

static int core_register() {
	int i;
	int r;

	for (i = 0; i < LQ_CFG_LAST; i++) {
		r = lq_config_register(config_core_typs[i], config_core_name[i]);
		if (r == -1) {
			return ERR_INIT;
		}
	}
	return ERR_OK;
}

int lq_config_init() {
	config.mem = lq_alloc(LQ_CONFIG_MEMCAP);
	if (config.mem == NULL) {
		return ERR_MEM;
	}
	config.members = lq_alloc(LQ_CONFIG_MAX * sizeof(void**));
	if (config.members == NULL) {
		lq_free(config.mem);
		return ERR_MEM;
	}
	config.typs = lq_alloc(LQ_CONFIG_MAX * sizeof(void*));
	if (config.typs == NULL) {
		lq_free(config.members);
		lq_free(config.mem);
		return ERR_MEM;
	}
	config_idx = lq_alloc(LQ_CONFIG_MAX * sizeof(char**));
	config.last = 0;
	config.len = 0;
	config.cap = LQ_CONFIG_MEMCAP;
	*config.members = config.mem;
	return core_register();
}

int lq_config_register(enum lq_typ_e typ, const char *name) {
	size_t l;

	switch (typ) {
		case LQ_TYP_VOID:
			l = sizeof(void*);
			break;
		case LQ_TYP_STR:
			l = sizeof(char*);
			break;
		case LQ_TYP_NUM:
			l = sizeof(long*);
			break;
		default:
			l = 0;
	}

	if (!l) {
		return -1;
	}
	*(config.typs+config.last) = typ;
	*(config_idx + config.last) = name; // name must survive, or NULL for no reverse.
	l = config.last;
	config.last++;

	return (int)l;
}

int lq_config_set(int k, void *v) {
	void *p;
	size_t l;

	if (k >= config.last) {
		return ERR_OVERFLOW;
	}

	switch (*(config.typs+k)) {
		case LQ_TYP_VOID:
			l = sizeof(void*);
			break;
		case LQ_TYP_STR:
			l = strlen((char*)v) + 1;
			break;
		case LQ_TYP_NUM:
			l = sizeof(long*);
			break;
		default:
			l = 0;
	}

	if (config.len + l > config.cap) {
		return ERR_OVERFLOW;
	}
	
	p = config.mem + config.len;
	*(config.members + k) = p;
	p = lq_cpy(p, v, l);
	if (p == NULL) {
		return ERR_WRITE;
	}
	config.len += l;
	return ERR_OK;
}

int lq_config_get(int k, void **r) {
	if (k >= config.last) {
		return ERR_OVERFLOW;
	}

	*r = *(config.members + k);
	
	return ERR_OK;
}

void lq_config_free() {
	lq_free(config_idx);
	lq_free(config.typs);
	lq_free(config.members);
	lq_free(config.mem);
}
