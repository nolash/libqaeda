#include "lq/err.h"
#include "lq/mem.h"
#include "lq/config.h"

const int lq_config_core_typs[] = {
	LQ_TYP_STR,
};

static struct config_t {
	void *members;
	enum  lq_typ_e *typs;
	size_t last;
} config;

static int core_apply() {
	int i;
	int r;

	for (i = 0; i < LQ_CFG_LAST; i++) {
		r = lq_config_register(lq_config_core_typs[i]);
		if (r) {
			return r;
		}
	}
	return ERR_OK;
}

int lq_config_init() {
	config.members = lq_alloc(LQ_CONFIG_MAX * sizeof(void*));
	if (config.members == NULL) {
		return ERR_MEM;
	}
	config.typs = lq_alloc(LQ_CONFIG_MAX * sizeof(void*));
	if (config.typs == NULL) {
		lq_free(config.members);
		return ERR_MEM;
	}
	config.last = 0;
	return core_apply();
}

int lq_config_register(enum lq_typ_e typ) {
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
		return ERR_INIT;
	}
	*(config.typs+config.last) = typ;
	config.last++;

	return ERR_OK;
}

int lq_config_set(char typ, int k, void *v) {
	return ERR_OK;
}

int lq_config_get(int k, void *r) {
	return ERR_OK;
}

void lq_config_free() {
	lq_free(config.typs);
	lq_free(config.members);
}
