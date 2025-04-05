#include <rerr.h>

#include "err.h"


#ifdef RERR
static char *_rerr[5] = {
	"",
	"Invalid request",
	"Invalid response",
	"Not resolved",
	"Unclean exit",
};

static char *_rerr_crypto[12] = {
	"",
	"Crypto backend",
	"Key fail",
	"Key storage fail",
	"Key unlock",
	"Key lock",
	"Sign reject",
	"No key found",
	"Encryption",
	"Digest",
	"Signature",
	"Invalid signature",
};

static char *_rerr_store[2] = {
	"",
	"Store unavailable",
};

static char *_rerr_cert[3] = {
	"",
	"Duplicate message",
	"Wrong message sequence",
};
#endif

void lq_err_init() {
#ifdef RERR
	rerr_init("base");
	rerr_register(RERR_PFX_LQ, "lq", _rerr);
	rerr_register(RERR_PFX_CRYPTO, "crypto", _rerr_crypto);
	rerr_register(RERR_PFX_STORE, "store", _rerr_store);
	rerr_register(RERR_PFX_CERT, "cert", _rerr_cert);
#endif
}
