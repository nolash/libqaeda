#include <llog.h>
#include <stdio.h>

#include "err.h"
#include "config.h"
#include "debug.h"
#include "asn.h"
#include "base.h"

static LQVersion version = {0, 1, 0};
static char version_string[128];

char zeros[65];

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
	lq_asn_finish();
}

LQVersion* lq_version() {
	return &version;
}

const char* lq_version_string() {
	sprintf(version_string, "%i.%i.%i", version.major, version.minor, version.patch);
	return (const char*)version_string;
}
