#include "err.h"
#include "config.h"


int lq_init() {
	char err[1024];
	int r;


	lq_err_init();
	return lq_config_init();
}

void lq_finish() {
	lq_config_free();
}
