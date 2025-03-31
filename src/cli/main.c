#include <stdlib.h>
#include <string.h>

#include <basedir.h>
#include <cwalk.h>

#include <lq/base.h>
#include <lq/crypto.h>
#include <lq/config.h>
#include <lq/io.h>
#include <lq/err.h>

static xdgHandle xdg;
static LQPrivKey *pk;


int lq_ui_init() {
	int r;
	char *path[8];
	char outpath[LQ_PATH_MAX];

	xdgInitHandle(&xdg);
	lq_init();

	path[0] = (char*)xdgCacheHome(&xdg);
	path[1] = "libqaeda";
	path[2] = NULL;
	cwk_path_join_multiple((const char**)path, outpath, LQ_PATH_MAX);
	ensuredir(outpath);

	r = lq_config_set(LQ_CFG_DIR_BASE, outpath);
	if (r) {
		return ERR_FAIL;
	}
	r = lq_config_set(LQ_CFG_DIR_DATA, outpath);
	if (r) {
		return ERR_FAIL;
	}
	r = lq_crypto_init(outpath);
	if (r) {
		return ERR_FAIL;
	}

	return ERR_OK;
}

void lq_ui_free() {
	xdgWipeHandle(&xdg);
	lq_crypto_free();
	lq_finish();
}

static LQPrivKey *get_key(const char *passphrase) {
	return lq_privatekey_load(passphrase, strlen(passphrase), NULL);
}

int main(int argc, char **argv) {
	int r;
	LQCert *cert;
	LQMsg *req;
	LQMsg *res;
	LQCtx ctx;

	r = lq_ui_init();
	if (r) {
		return 1;
	}
	pk = get_key(*(argv+1));
	if (pk == NULL) {
		lq_ui_free();
		return 1;
	}

	lq_privatekey_free(pk);
	lq_ui_free();
}
