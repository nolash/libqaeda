#include <libtasn1.h>
#include <llog.h>

#include "lq/wire.h"
#include "err.h"
#include "config.h"
#include "debug.h"


asn1_node asn;

char zeros[65];

int lq_init() {
	int r;

	r = asn1_array2tree(defs_asn1_tab, &asn, NULL);
	if (r != ASN1_SUCCESS) {
		return debug_logerr(LLOG_ERROR, ERR_INIT, "asn init");
	}

	lq_err_init();
	return lq_config_init();
}

void lq_finish() {
	int r;

	r = asn1_delete_structure(&asn);
	if (r != ASN1_SUCCESS) {
		debug_logerr(LLOG_ERROR, ERR_UNCLEAN, "asn exit");
	}

	lq_config_free();
}
