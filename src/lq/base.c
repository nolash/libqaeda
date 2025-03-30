#include "err.h"
#include "config.h"


int lq_init() {
	int r;

	lq_err_init();
	r = lq_config_init();
	return r;
}

