#include <stddef.h>
#include <libtasn1.h>

#include "lq/cert.h"
#include "lq/mem.h"
#include "lq/wire.h"
#include "lq/err.h"

static LQCert noparent;
static LQMsg nomsg = {
	.data = "",
	.len = 0,
	.time.tv_sec = 0,
	.time.tv_nsec = 0,
};

LQCert* lq_certificate_new(LQCert *parent, LQCtx *ctx, LQMsg *req, LQMsg *rsp) {
	LQCert *cert;

	cert = lq_alloc(sizeof(LQCert));
	if (parent != NULL) {
		cert->parent = parent;
	} else {
		cert->parent = &noparent;
	}
	cert->request = req;
	cert->response = rsp;
	cert->ctx = ctx;
	lq_set(cert->domain, 0, LQ_CERT_DOMAIN_LEN);

	return cert;
}

int lq_certificate_serialize(LQCert *cert, char *out, size_t *out_len) {
	size_t c;
	int r;
	size_t mx;
	char err[1024];
	char buf[4096];
	LQMsg *msg;
	asn1_node node;

	mx = *out_len;
	*out_len = 0;
	lq_set(&node, 0, sizeof(node));
	r = asn1_array2tree(defs_asn1_tab, &node, err);
	if (r != ASN1_SUCCESS) {
		return ERR_INIT;
	}

	c = LQ_CERT_DOMAIN_LEN;
	*out_len += c;
	if (*out_len > mx) {
		return ERR_OVERFLOW;
	}
	r = asn1_write_value(node, "Qaeda.Cert.domain", cert->domain, c);
	if (r != ASN1_SUCCESS) {
		return ERR_WRITE;
	}

	msg = cert->request;
	if (msg == NULL) {
		msg = &nomsg;
	}
	c = mx - LQ_CERT_DOMAIN_LEN; 
	r = lq_msg_serialize(msg, buf, &c);
	if (r != ERR_OK) {
		return r;
	}
	*out_len += c;
	if (*out_len > mx) {
		return ERR_OVERFLOW;
	}
	r = asn1_write_value(node, "Qaeda.Cert.request", buf, c);
	if (r != ASN1_SUCCESS) {
		return ERR_WRITE;
	}

	return ERR_OK;
}

void lq_certificate_free(LQCert *cert) {
	lq_free(cert);
}
