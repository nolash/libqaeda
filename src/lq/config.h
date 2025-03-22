#ifndef LQ_CONFIG_H_
#define LQ_CONFIG_H_

#ifndef LQ_CONFIG_MEMCAP
#define LQ_CONFIG_MEMCAP 65536
#endif

#ifndef LQ_CONFIG_MAX
#define LQ_CONFIG_MAX 128
#endif

#include "lq/mem.h"

enum lq_config_core_e {
	LQ_CFG_DATA,
	LQ_CFG_LAST,
};


int lq_config_init();
int lq_config_register(enum lq_typ_e typ);
int lq_config_set(int k, void *v); 
int lq_config_get(int k, void **r);
void lq_config_free();

#endif
