#include <libtasn1.h>
#include <llog.h>

#include "err.h"
#include "config.h"
#include "debug.h"

char zeros[65];

int lq_asn_init();

int lq_init() {
	int r;

	r = lq_asn_init();
	if (r != ERR_OK) {
		return debug_logerr(LLOG_ERROR, ERR_INIT, "asn init");
	}
	lq_err_init();
	return lq_config_init();
}

void lq_finish() {
//	int r;
//
//	r = asn1_delete_structure(&asn);
//	if (r != ASN1_SUCCESS) {
//		debug_logerr(LLOG_ERROR, ERR_UNCLEAN, "asn exit");
//	}
//
	lq_config_free();
}
