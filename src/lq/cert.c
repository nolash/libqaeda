#include "lq/cert.h"
#include "lq/mem.h"


LQCert* lq_certificate_new(LQCert *parent, LQCtx *ctx, LQMsg *req, LQMsg *rsp) {
	LQCert *cert;

	cert = lq_alloc(sizeof(LQCert));
	cert->parent = parent;
	cert->request = req;
	cert->response = rsp;
	cert->ctx = ctx;

	return cert;
}

void lq_certificate_free(LQCert *cert) {
	lq_free(cert);
}
