#include <stddef.h>

#include <libtasn1.h>
#include <llog.h>

#include "lq/cert.h"
#include "lq/mem.h"
#include "lq/wire.h"
#include "lq/err.h"
#include "lq/store.h"
#include "debug.h"


extern asn1_node asn;

extern char zeros[65];
static LQPubKey nokey = {
	.pk = 0,
	.impl = zeros,
};

static LQMsg nomsg = {
	.state = 0,
	.data = "",
	.len = 0,
	.time.tv_sec = 0,
	.time.tv_nsec = 0,
};
static LQSig nosig = {
	.pubkey = &nokey,
	.impl = zeros,
};

LQCert* lq_certificate_new(LQCert *parent) {
	LQCert *cert;

	cert = lq_alloc(sizeof(LQCert));
	lq_zero(cert, sizeof(LQCert));
	cert->parent = parent;

	return cert;
}

int lq_certificate_request(LQCert *cert, LQMsg *req, LQPrivKey *pk) {
	int r;

	r = ERR_OK;
	if (cert->request != NULL) {
		return ERR_DUP;
	}
	cert->request = req;
	if (pk != NULL) {
		r = lq_certificate_sign(cert, pk);
	}
	return r;
}

int lq_certificate_respond(LQCert *cert, LQMsg *res, LQPrivKey *pk) {
	int r;

	if (cert->request_sig == NULL) {
		return ERR_SEQ;
	}
	if (cert->response != NULL) {
		return ERR_DUP;
	}
	cert->response = res;
	if (pk != NULL) {
		r = lq_certificate_sign(cert, pk);
	}
	return r;
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
	char data[LQ_BLOCKSIZE];
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
		
		debug(LLOG_INFO, "cert", "signed response");
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
	debug(LLOG_INFO, "cert", "signed request");
	return ERR_OK;
}

int lq_certificate_verify(LQCert *cert, LQPubKey **request_pubkey, LQPubKey **response_pubkey) {
	int r;
	char out[LQ_BLOCKSIZE];
	LQCert cert_valid;

	if (cert->request_sig == NULL) {
		return debug_logerr(LLOG_DEBUG, ERR_NOOP, "no signatures");
	}

	lq_cpy(&cert_valid, cert, sizeof(LQCert));
	cert_valid.request_sig = NULL;
	cert_valid.response = NULL;
	cert_valid.response_sig = NULL;
	r = state_digest(&cert_valid, out, 0);
	if (r != ERR_OK) {
		return debug_logerr(LLOG_DEBUG, r, "cert state request");
	}

	r = lq_msg_verify_extra(cert->request, cert->request_sig, NULL, out, LQ_DIGEST_LEN);
	if (r != ERR_OK) {
		return debug_logerr(LLOG_DEBUG, r, "cert verify request");
	}

	if (cert->response_sig == NULL) {
		debug(LLOG_DEBUG, "cert", "skip empty response signature");
		return ERR_OK;
	}

	cert_valid.request_sig = cert->request_sig;
	cert_valid.response = cert->response;
	r = state_digest(&cert_valid, out, 0);
	if (r != ERR_OK) {
		return debug_logerr(LLOG_DEBUG, r, "cert state response");
	}
	cert_valid.response_sig = cert->response_sig;

	r = lq_msg_verify_extra(cert_valid.response, cert_valid.response_sig, NULL, out, LQ_DIGEST_LEN);
	if (r != ERR_OK) {
		return debug_logerr(LLOG_DEBUG, r, "cert verify response");
	}

	if (request_pubkey != NULL) {
		*request_pubkey = cert->request_sig->pubkey;
	}

	if (response_pubkey != NULL) {
		if (cert_valid.response_sig != NULL) {
			*response_pubkey = cert->response_sig->pubkey;
		}
	}

	return ERR_OK;
}

// TODO: DRY
static int asn_except(asn1_node *node, int err) {
	int r;

	r = asn1_delete_structure(node);
	if (r != ASN1_SUCCESS) {
		debug_logerr(LLOG_ERROR, ERR_FAIL, "free cert asn");
	}

	return err;
}

int lq_certificate_serialize(LQCert *cert, LQResolve *resolve, char *out, size_t *out_len) {
	size_t c;
	int r;
	size_t mx;
	char err[LQ_ERRSIZE];
	char buf[LQ_BLOCKSIZE];
	LQMsg *msg;
	LQSig *sig;
	asn1_node item;
	char *sigdata;

	mx = *out_len;
	*out_len = 0;
	lq_zero(&item, sizeof(item));

	r = asn1_create_element(asn, "Qaeda", &item);
	if (r != ASN1_SUCCESS) {
		return ERR_READ;
	}

	c = LQ_CERT_DOMAIN_LEN;
	*out_len += c;
	if (*out_len > mx) {
		return asn_except(&item, ERR_OVERFLOW);
	}
	r = asn1_write_value(item, "Cert.domain", cert->domain, c);
	if (r != ASN1_SUCCESS) {
		return asn_except(&item, ERR_WRITE);
	}

	// Set request message if exists
	msg = cert->request;
	if (msg == NULL) {
		msg = &nomsg;
	}
	c = mx - LQ_CERT_DOMAIN_LEN; 
	r = lq_msg_serialize(msg, resolve, buf, &c);
	if (r != ERR_OK) {
		return asn_except(&item, r);
	}	
	*out_len += c;
	if (*out_len > mx) {
		return asn_except(&item, ERR_OVERFLOW);
	}
	r = asn1_write_value(item, "Cert.request", buf, c);
	if (r != ASN1_SUCCESS) {
		return asn_except(&item, ERR_WRITE);
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
		return asn_except(&item, ERR_OVERFLOW);
	}
	r = asn1_write_value(item, "Cert.request_sig", sigdata, c);
	if (r != ASN1_SUCCESS) {
		return asn_except(&item, ERR_WRITE);
	}
	
	msg = cert->response;
	if (msg == NULL) {
		msg = &nomsg;
	}
	c = mx - LQ_CERT_DOMAIN_LEN; 
	r = lq_msg_serialize(msg, resolve, buf, &c);
	if (r != ERR_OK) {
		return asn_except(&item, r);
	}
	*out_len += c;
	if (*out_len > mx) {
		return asn_except(&item, ERR_OVERFLOW);
	}
	r = asn1_write_value(item, "Cert.response", buf, c);
	if (r != ASN1_SUCCESS) {
		return asn_except(&item, ERR_WRITE);
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
		return asn_except(&item, ERR_OVERFLOW);
	}
	r = asn1_write_value(item, "Cert.response_sig", sigdata, c);
	if (r != ASN1_SUCCESS) {
		return asn_except(&item, ERR_WRITE);
	}

	if (cert->parent == NULL) {
		c = 0;
		r = asn1_write_value(item, "Cert.parent", &c, 1);
		if (r != ASN1_SUCCESS) {
			return asn_except(&item, ERR_WRITE);
		}
	} else {
		r = state_digest(cert, cert->parent_hash, 1);
		if (r != ERR_OK) {
			return asn_except(&item, r);
		}
		c = LQ_DIGEST_LEN;
		r = asn1_write_value(item, "Cert.parent", cert->parent_hash, c);
		if (r != ASN1_SUCCESS) {
			return asn_except(&item, ERR_WRITE);
		}
	}

	*out_len = mx;
	r = asn1_der_coding(item, "Cert", out, (int*)out_len, err);
	if (r != ASN1_SUCCESS) {
		return asn_except(&item, ERR_ENCODING);
	}

	r = asn1_delete_structure(&item);
	if (r != ASN1_SUCCESS) {
		return ERR_FAIL;
	}

	return ERR_OK;
}

/**
 * \todo pubkey is copied to signature from message, to prevent a double-free. Wastes up to 2x sig bytes.
 *
 */
int lq_certificate_deserialize(LQCert **cert, LQResolve *resolve, char *in, size_t in_len) {
	int r;
	int c;
	char err[LQ_ERRSIZE];
	char tmp[LQ_BLOCKSIZE];
	asn1_node item;
	LQCert *p;

	lq_zero(&item, sizeof(item));
	
	r = asn1_create_element(asn, "Qaeda.Cert", &item);
	if (r != ASN1_SUCCESS) {
		return ERR_READ;
	}

	r = asn1_der_decoding(&item, in, in_len, err);
	if (r != ASN1_SUCCESS) {
		return asn_except(&item, ERR_ENCODING);
	}

	c = LQ_CERT_DOMAIN_LEN;
	r = asn1_read_value(item, "domain", tmp, &c);
	if (r != ASN1_SUCCESS) {
		return asn_except(&item, ERR_READ);
	}

	*cert = lq_certificate_new(NULL);
	p = *cert;
	lq_certificate_set_domain(p, tmp);

	c = LQ_BLOCKSIZE;
	r = asn1_read_value(item, "request", tmp, &c);
	if (r != ASN1_SUCCESS) {
		return asn_except(&item, ERR_READ);
	}
	r = lq_msg_deserialize(&p->request, resolve, tmp, c);
	if (r != ERR_OK) {
		return asn_except(&item, r);
	}
	if (p->request != NULL) {
		c = LQ_BLOCKSIZE;
		r = asn1_read_value(item, "request_sig", tmp, &c);
		if (r != ASN1_SUCCESS) {
			lq_msg_free(p->request);
			return asn_except(&item, ERR_READ);
		}
		if (c > 0) {
			p->request_sig = lq_signature_from_bytes(tmp, c, p->request->pubkey);
		}
	}

	c = LQ_BLOCKSIZE;
	r = asn1_read_value(item, "response", tmp, &c);
	if (r != ASN1_SUCCESS) {
		lq_signature_free(p->request_sig);
		lq_msg_free(p->request);
		return asn_except(&item, ERR_READ);
	}
	r = lq_msg_deserialize(&p->response, resolve, tmp, c);
	if (r != ERR_OK) {
		lq_signature_free(p->request_sig);
		lq_msg_free(p->request);
		return asn_except(&item, r);
	}
	if (p->response != NULL) {
		c = LQ_BLOCKSIZE;
		r = asn1_read_value(item, "response_sig", tmp, &c);
		if (r != ASN1_SUCCESS) {
			lq_msg_free(p->response);
			lq_signature_free(p->request_sig);
			lq_msg_free(p->request);
			return asn_except(&item, ERR_READ);
		}
		if (c > 0) {
			p->response_sig = lq_signature_from_bytes(tmp, c, p->response->pubkey);
		}
	}

	c = 4096;
	r = asn1_read_value(item, "parent", tmp, &c);
	if (r != ASN1_SUCCESS) {
		lq_signature_free(p->response_sig);
		lq_msg_free(p->response);
		lq_signature_free(p->request_sig);
		lq_msg_free(p->request);
		return asn_except(&item, ERR_READ);
	}
	p->parent = NULL;
	if (c == 1) {
		lq_zero(p->parent_hash, LQ_DIGEST_LEN);
	} else {
		lq_cpy(p->parent_hash, tmp, LQ_DIGEST_LEN);
	}
	// \todo render parent if set

	r = asn1_delete_structure(&item);
	if (r != ASN1_SUCCESS) {
		return ERR_FAIL;
	}

	return ERR_OK;
}

void lq_certificate_free(LQCert *cert) {
	if (cert->request != NULL) {
		lq_msg_free(cert->request);
	}
	if (cert->request_sig != NULL) {
		lq_signature_free(cert->request_sig);
	}
	if (cert->response != NULL) {
		lq_msg_free(cert->response);
	}
	if (cert->response_sig != NULL) {
		lq_signature_free(cert->response_sig);
	}
	lq_free(cert);
}
