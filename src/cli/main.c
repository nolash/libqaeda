#include <stdlib.h>
#include <string.h>

#include <basedir.h>
#include <cwalk.h>

#include <lq/base.h>
#include <lq/crypto.h>
#include <lq/config.h>
#include <lq/io.h>
#include <lq/err.h>
#include <lq/cert.h>
#include <lq/msg.h>

#define INIT_LQ 0x01
#define INIT_CRYPTO 0x02
#define INIT_ALICE 0x04
#define INIT_BOB 0x08

static int init_state;
static xdgHandle xdg;
static LQPrivKey *pk_alice;
static LQPubKey *pubk_alice;
static LQPrivKey *pk_bob;
static LQPubKey *pubk_bob;
char passphrase_alice[] = "1234";
char passphrase_bob[] = "5678";


int lq_ui_init() {
	int r;
	char *path[8];
	char outpath[LQ_PATH_MAX];

	xdgInitHandle(&xdg);
	lq_init();
	init_state |= INIT_LQ;

	// Set up storage path.
	path[0] = (char*)xdgCacheHome(&xdg);
	path[1] = "libqaeda";
	path[2] = NULL;
	cwk_path_join_multiple((const char**)path, outpath, LQ_PATH_MAX);
	ensuredir(outpath);

	// Set up configuration.
	r = lq_config_set(LQ_CFG_DIR_BASE, outpath);
	if (r) {
		return ERR_FAIL;
	}
	r = lq_config_set(LQ_CFG_DIR_DATA, outpath);
	if (r) {
		return ERR_FAIL;
	}

	// Initialize crypto subsystem.
	r = lq_crypto_init(outpath);
	if (r) {
		return ERR_FAIL;
	}

	return ERR_OK;
}

void lq_ui_free() {
	if (init_state & INIT_BOB) {
		lq_publickey_free(pubk_bob);
		lq_privatekey_free(pk_bob);
	}
	if (init_state & INIT_ALICE) {
		lq_publickey_free(pubk_alice);
		lq_privatekey_free(pk_alice);
	}
	if (init_state & INIT_CRYPTO) {
		lq_crypto_free();
	}
	if (init_state & INIT_LQ) {
		xdgWipeHandle(&xdg);
		lq_finish();
	}
}


int main(int argc, char **argv) {
	int r;
	LQCert *cert;
	LQMsg *req;
	LQMsg *res;

	r = lq_ui_init();
	if (r) {
		return 1;
	}

	pk_alice = lq_privatekey_load(passphrase_alice, strlen(passphrase_alice), NULL);
	if (pk_alice == NULL) {
		lq_ui_free();
		return 1;
	}
	pubk_alice = lq_publickey_from_privatekey(pk_alice);
	if (pubk_alice == NULL) {
		lq_ui_free();
		return 1;
	}
	pk_bob = lq_privatekey_load(passphrase_bob, strlen(passphrase_bob), NULL);
	if (pk_bob == NULL) {
		lq_ui_free();
		return 1;
	}
	pubk_bob = lq_publickey_from_privatekey(pk_bob);
	if (pubk_bob == NULL) {
		lq_ui_free();
		return 1;
	}

	req = lq_msg_new("foo", 4);
	if (req == NULL) {
		lq_ui_free();
		return 1;
	}
	cert = lq_certificate_new(NULL);
	r = lq_certificate_request(cert, req, pk_alice);
	if (r != ERR_OK) {
		lq_ui_free();
		return 1;
	}

	res = lq_msg_new("foo", 4);
	if (res == NULL) {
		lq_ui_free();
		return 1;
	}
	r = lq_certificate_respond(cert, res, pk_bob);
	if (r != ERR_OK) {
		lq_ui_free();
		return 1;
	}

	r = lq_certificate_verify(cert, pubk_alice, NULL);

	lq_ui_free();
}
