#include <rerr.h>

#include "err.h"


#ifdef RERR
static char *_rerr[3] = {
	"",
	"Invalid request",
	"Invalid response",
};

static char *_rerr_crypto[10] = {
	"",
	"Crypto backend",
	"Auth fail",
	"Key storage fail",
	"Sign reject",
	"Resource fail",
	"No key found",
	"Encryption",
	"Signature",
	"Invalid signature",
};

static char *_rerr_store[2] = {
	"",
	"Store unavailable",
};
#endif

void lq_err_init() {
#ifdef RERR
	rerr_init("base");
	rerr_register(RERR_PFX_LQ, "lq", _rerr);
	rerr_register(RERR_PFX_CRYPTO, "crypto", _rerr_crypto);
	rerr_register(RERR_PFX_STORE, "store", _rerr_store);
#endif
}
