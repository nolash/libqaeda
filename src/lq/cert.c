#include <stddef.h>
#include <libtasn1.h>

#include "lq/cert.h"
#include "lq/mem.h"
#include "lq/wire.h"
#include "lq/err.h"
#include "lq/store.h"

static char zeros[65];
static LQPubKey nokey = {
	.pk = 0,
	.impl = zeros,
};

static LQMsg nomsg = {
	.data = "",
	.len = 0,
	.time.tv_sec = 0,
	.time.tv_nsec = 0,
};
static LQSig nosig = {
	.pubkey = &nokey,
	.impl = zeros,
};

LQCert* lq_certificate_new(LQCert *parent, LQCtx *ctx, LQMsg *req, LQMsg *rsp) {
	LQCert *cert;

	cert = lq_alloc(sizeof(LQCert));
	cert->parent = parent;
	cert->request = req;
	cert->request_sig = NULL;
	cert->response = rsp;
	cert->response_sig = NULL;
	lq_set(cert->domain, 0, LQ_CERT_DOMAIN_LEN);

	return cert;
}

void lq_certificate_set_domain(LQCert *cert, const char *domain) {
	lq_cpy(cert->domain, domain, LQ_CERT_DOMAIN_LEN);
}

// generates a prefix to include with the message for the signature
// domain (required)
// parent (optional)
// request signature (optional)
// response signature (optional)
static int state_digest(LQCert *cert, char *out, int final) {
	int r;
	int c;
	char data[1024];
	char *p;
	char *sigdata;
	size_t siglen;

	c = LQ_CERT_DOMAIN_LEN;
	p = data;
	lq_cpy(p, cert->domain, c);
	p += c;

	if (cert->parent != NULL && !final) {
		r = state_digest(cert->parent, cert->parent_hash, 1);
		if (r != ERR_OK) {
			return r;
		}
		lq_cpy(p, cert->parent_hash, LQ_DIGEST_LEN);
		c += LQ_DIGEST_LEN;
		p += LQ_DIGEST_LEN;
	}

	if (cert->request_sig != NULL) {
		siglen = lq_signature_bytes(cert->request_sig, &sigdata);
		lq_cpy(p, sigdata, siglen);
		c += siglen;
		p += siglen;
	}

	if (cert->response_sig != NULL) {
		siglen = lq_signature_bytes(cert->response_sig, &sigdata);
		lq_cpy(p, sigdata, siglen);
		c += siglen;
		p += siglen;
	} else if (final) {
		return ERR_RESPONSE;
	}

	return lq_digest(data, c, out);
}

int lq_certificate_sign(LQCert *cert, LQPrivKey *pk) {
	int r;
	char out[LQ_DIGEST_LEN];

	r = state_digest(cert, out, 0);
	if (r != ERR_OK) {
		return r;
	}
	if (cert->response != NULL) {
		if (cert->response_sig != NULL) {
			return ERR_RESPONSE;
		}
		if (cert->request == NULL) {
			return ERR_INIT;	
		}
		cert->response_sig = lq_msg_sign_extra(cert->response, pk, NULL, out, LQ_DIGEST_LEN);
		if (cert->response_sig == NULL) {
			return ERR_ENCODING;
		}
		return ERR_OK;
	}
	if (cert->request == NULL) {
		return ERR_INIT;
	}
	if (cert->request_sig != NULL) {
		return ERR_REQUEST;
	}
	cert->request_sig = lq_msg_sign_extra(cert->request, pk, NULL, out, LQ_DIGEST_LEN);
	if (cert->request_sig == NULL) {
		return ERR_ENCODING;
	}
	return ERR_OK;
}

int lq_certificate_serialize(LQCert *cert, char *out, size_t *out_len, LQResolve *resolve) {
	size_t c;
	int r;
	size_t mx;
	char err[1024];
	char buf[4096];
	LQMsg *msg;
	LQSig *sig;
	asn1_node node;
	char *sigdata;

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

	// Set request message if exists
	msg = cert->request;
	if (msg == NULL) {
		msg = &nomsg;
	}
	c = mx - LQ_CERT_DOMAIN_LEN; 
	r = lq_msg_serialize(msg, buf, &c, resolve);
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

	// Set request signature if exists
	sig = cert->request_sig;
	if (cert->request == NULL || sig == NULL) {
		sig = &nosig;
	}
	// \todo proper sig serialize
	c = lq_signature_bytes(sig, &sigdata);
	*out_len += c;
	if (*out_len > mx) {
		return ERR_OVERFLOW;
	}
	r = asn1_write_value(node, "Qaeda.Cert.request_sig", sigdata, c);
	if (r != ASN1_SUCCESS) {
		return ERR_WRITE;
	}
	
	msg = cert->response;
	if (msg == NULL) {
		msg = &nomsg;
	}
	c = mx - LQ_CERT_DOMAIN_LEN; 
	r = lq_msg_serialize(msg, buf, &c, resolve);
	if (r != ERR_OK) {
		return r;
	}
	*out_len += c;
	if (*out_len > mx) {
		return ERR_OVERFLOW;
	}
	r = asn1_write_value(node, "Qaeda.Cert.response", buf, c);
	if (r != ASN1_SUCCESS) {
		return ERR_WRITE;
	}

	// Set response signature if exists
	sig = cert->response_sig;
	if (cert->response == NULL || sig == NULL) {
		sig = &nosig;
	}
	// \todo proper sig serialize
	c = lq_signature_bytes(sig, &sigdata);
	*out_len += c;
	if (*out_len > mx) {
		return ERR_OVERFLOW;
	}
	r = asn1_write_value(node, "Qaeda.Cert.response_sig", sigdata, c);
	if (r != ASN1_SUCCESS) {
		return ERR_WRITE;
	}

	if (cert->parent == NULL) {
		c = 0;
		r = asn1_write_value(node, "Qaeda.Cert.parent", &c, 1);
		if (r != ASN1_SUCCESS) {
			return ERR_WRITE;
		}
	} else {
		r = state_digest(cert, cert->parent_hash, 1);
		if (r != ERR_OK) {
			return r;
		}
		c = LQ_DIGEST_LEN;
		r = asn1_write_value(node, "Qaeda.Cert.parent", cert->parent_hash, c);
		if (r != ASN1_SUCCESS) {
			return ERR_WRITE;
		}
	}

	*out_len = mx;
	r = asn1_der_coding(node, "Qaeda.Cert", out, (int*)out_len, err);
	if (r != ASN1_SUCCESS) {
		return ERR_ENCODING;
	}

	return ERR_OK;
}

int lq_certificate_deserialize(LQCert **cert, char *in, size_t in_len, LQResolve *resolve) {
	int r;
	int c;
	char err[1024];
	char tmp[4096];
	asn1_node node;
	asn1_node item;
	LQCtx ctx;
	LQCert *p;

	// \todo ctx make it make sense here
	lq_set(&ctx, 0, sizeof(LQCtx));
	lq_set(&node, 0, sizeof(node));
	lq_set(&item, 0, sizeof(item));
	r = asn1_array2tree(defs_asn1_tab, &node, err);
	if (r != ASN1_SUCCESS) {
		return ERR_INIT;
	}

	r = asn1_create_element(node, "Qaeda.Cert", &item);
	if (r != ASN1_SUCCESS) {
		return ERR_READ;
	}

	r = asn1_der_decoding(&item, in, in_len, err);
	if (r != ASN1_SUCCESS) {
		return ERR_ENCODING;
	}

	c = LQ_CERT_DOMAIN_LEN;
	r = asn1_read_value(item, "domain", tmp, &c);
	if (r != ASN1_SUCCESS) {
		return ERR_READ;
	}

	p = lq_certificate_new(NULL, &ctx, NULL, NULL);
	lq_certificate_set_domain(p, tmp);

	c = 4096;
	r = asn1_read_value(item, "request", tmp, &c);
	if (r != ASN1_SUCCESS) {
		return ERR_READ;
	}
	r = lq_msg_deserialize(&p->request, tmp, c, resolve);
	if (r != ERR_OK) {
		return r;
	}

	c = 4096;
	r = asn1_read_value(item, "request_sig", tmp, &c);
	if (r != ASN1_SUCCESS) {
		return ERR_READ;
	}
	if (c > 0) {
		p->request_sig = lq_signature_from_bytes(tmp, c, NULL);
	}

	c = 4096;
	r = asn1_read_value(item, "response", tmp, &c);
	if (r != ASN1_SUCCESS) {
		return ERR_READ;
	}
	r = lq_msg_deserialize(&p->response, tmp, c, resolve);
	if (r != ERR_OK) {
		return r;
	}


	c = 4096;
	r = asn1_read_value(item, "response_sig", tmp, &c);
	if (r != ASN1_SUCCESS) {
		return ERR_READ;
	}
	if (c > 0) {
		p->response_sig = lq_signature_from_bytes(tmp, c, NULL);
	}

	c = 4096;
	r = asn1_read_value(item, "parent", tmp, &c);
	if (r != ASN1_SUCCESS) {
		return ERR_READ;
	}
	p->parent = NULL;
	if (c == 1) {
		lq_set(p->parent_hash, 0, LQ_DIGEST_LEN);
	} else {
		lq_cpy(p->parent_hash, tmp, LQ_DIGEST_LEN);
	}
	// \todo render parent if set

	*cert = p;

	return ERR_OK;
}

void lq_certificate_free(LQCert *cert) {
	lq_free(cert);
}
