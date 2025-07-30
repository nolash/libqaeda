#include <stddef.h>

#include <llog.h>

#include "lq/cert.h"
#include "lq/mem.h"
#include "lq/err.h"
#include "lq/store.h"
#include "lq/asn.h"
#include "debug.h"


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

int lq_certificate_set_parent_digest(LQCert *cert, const char *b) {
	if (cert->parent != NULL) {
		return ERR_DUP;
	}
	lq_cpy(cert->parent_hash, b, LQ_DIGEST_LEN);
	return ERR_OK;
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

	r = ERR_OK;
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

static int certificate_state(LQCert *cert) {
	int r;

	r = 0;
	if (lq_cmp(cert->parent_hash, zeros, LQ_DIGEST_LEN)) {
		r = CERT_CHAIN;
	}

	if (cert->response_sig != NULL) {
		return r | CERT_RESPONSE;
	}
	if (cert->request_sig != NULL) {
		return r | CERT_REQUEST;
	}
	return r | CERT_NONE;
}

int lq_certificate_digest(LQCert *cert, LQResolve *resolve, char *out)  {
	int r;
	char buf[LQ_BLOCKSIZE];
	size_t c;

	if (!(certificate_state(cert) & CERT_RESPONSE)) {
		return ERR_NONSENSE;
	}

	c = LQ_BLOCKSIZE;
	r = lq_certificate_serialize(cert, resolve, buf, &c);
	if (r) {
		return ERR_FAIL;
	}
	r = lq_digest(buf, c, out);
	if (r) {
		return ERR_FAIL;
	}
	return ERR_OK;
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

/**
 * \todo DRY with lq_certificate_sign
 */
char* lq_certificate_mat(const LQCert *cert, const LQPubKey *pubk, char *out) {
	int r;
	char state[LQ_DIGEST_LEN];

	r = state_digest(cert, state, 0);
	if (r != ERR_OK) {
		return NULL;
	}

	if (cert->response != NULL) {
		if (cert->response_sig != NULL) {
			debug_logerr(LLOG_DEBUG, ERR_RESPONSE, "mat response sig");
			return NULL;
		}
		if (cert->request == NULL) {
			debug_logerr(LLOG_DEBUG, ERR_INIT, "mat response init");
			return NULL;
		}
		if (cert->response->pubkey == NULL) {
			cert->response->pubkey = pubk;
		}
		r = lq_msg_mat(cert->response, NULL, state, LQ_DIGEST_LEN, out);
		if (r) {
			debug_logerr(LLOG_DEBUG, ERR_ENCODING, "mat msg");
			return NULL;
		}
		
		debug(LLOG_INFO, "cert", "mat response");
		return out;
	}
	if (cert->request == NULL) {
		debug_logerr(LLOG_DEBUG, ERR_INIT, "mat req");
		return NULL;
	}
	if (cert->request_sig != NULL) {
		debug_logerr(LLOG_DEBUG, ERR_REQUEST, "mat req");
		return NULL;
	}
	if (cert->request->pubkey == NULL) {
		cert->request->pubkey = pubk;
	}
	r = lq_msg_mat(cert->request, NULL, state, LQ_DIGEST_LEN, out);
	if (r) {
		return NULL;
	}
	return out;
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

	if (request_pubkey != NULL) {
		*request_pubkey = cert->request_sig->pubkey;
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

	if (response_pubkey != NULL) {
		if (cert_valid.response_sig != NULL) {
			*response_pubkey = cert->response_sig->pubkey;
		}
	}

	return ERR_OK;
}

int lq_certificate_serialize(LQCert *cert, LQResolve *resolve, char *out, size_t *out_len) {
	size_t c;
	int r;
	size_t mx;
	char err[LQ_ERRSIZE];
	char buf[LQ_BLOCKSIZE];
	LQMsg *msg;
	LQSig *sig;
//	asn1_node item;
	LQASN *asn;
	char *sigdata;

	mx = *out_len;
	*out_len = 0;
//	lq_zero(&item, sizeof(item));

//	r = asn1_create_element(asn, "Qaeda", &item);
//	if (r != ASN1_SUCCESS) {
//		return ERR_READ;
//	}
	asn = lq_asn_new("Cert");
	if (asn == NULL) {
		return ERR_WRITE;
	}

	c = LQ_CERT_DOMAIN_LEN;
	*out_len += c;
	if (*out_len > mx) {
		//return asn_except(&item, ERR_OVERFLOW);
		lq_asn_free(asn);
		return ERR_OVERFLOW;
	}
//	r = asn1_write_value(item, "Cert.domain", cert->domain, c);
//	if (r != ASN1_SUCCESS) {
//		return asn_except(&item, ERR_WRITE);
//	}
	r = lq_asn_write(asn, "domain", cert->domain, c);
	if (r != ERR_OK) {
		return r;
	}

	// Set request message if exists
	msg = cert->request;
	if (msg == NULL) {
		msg = &nomsg;
	}
	c = mx - LQ_CERT_DOMAIN_LEN; 
	r = lq_msg_serialize(msg, resolve, buf, &c);
	if (r != ERR_OK) {
		//return asn_except(&item, r);
		lq_asn_free(asn);
		return r;
	}	
	*out_len += c;
	if (*out_len > mx) {
		//return asn_except(&item, ERR_OVERFLOW);
		lq_asn_free(asn);
		return ERR_OVERFLOW;
	}
//	r = asn1_write_value(item, "Cert.request", buf, c);
//	if (r != ASN1_SUCCESS) {
//		return asn_except(&item, ERR_WRITE);
//	}
	r = lq_asn_write(asn, "request", buf, c);
	if (r != ERR_OK) {
		return r;
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
		//return asn_except(&item, ERR_OVERFLOW);
		lq_asn_free(asn);
		return ERR_OVERFLOW;
	}
//	r = asn1_write_value(item, "Cert.request_sig", sigdata, c);
//	if (r != ASN1_SUCCESS) {
//		return asn_except(&item, ERR_WRITE);
//	}
	r = lq_asn_write(asn, "request_sig", sigdata, c);
	if (r != ERR_OK) {
		return r;
	}
	
	msg = cert->response;
	if (msg == NULL) {
		msg = &nomsg;
	}
	c = mx - LQ_CERT_DOMAIN_LEN; 
	r = lq_msg_serialize(msg, resolve, buf, &c);
	if (r != ERR_OK) {
		//return asn_except(&item, r);
		lq_asn_free(asn);
		return r;
	}
	*out_len += c;
	if (*out_len > mx) {
		//return asn_except(&item, ERR_OVERFLOW);
		lq_asn_free(asn);
		return ERR_OVERFLOW;
	}
//	r = asn1_write_value(item, "Cert.response", buf, c);
//	if (r != ASN1_SUCCESS) {
//		return asn_except(&item, ERR_WRITE);
//	}
	r = lq_asn_write(asn, "response", buf, c);
	if (r != ERR_OK) {
		return r;
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
		//return asn_except(&item, ERR_OVERFLOW);
		lq_asn_free(asn);
		return ERR_OVERFLOW;
	}
//	r = asn1_write_value(item, "Cert.response_sig", sigdata, c);
//	if (r != ASN1_SUCCESS) {
//		return asn_except(&item, ERR_WRITE);
//	}
	r = lq_asn_write(asn, "response_sig", sigdata, c);
	if (r != ERR_OK) {
		return r;
	}

	if (cert->parent == NULL) {
		c = 0;
//		r = asn1_write_value(item, "Cert.parent", &c, 1);
//		if (r != ASN1_SUCCESS) {
//			return asn_except(&item, ERR_WRITE);
//		}
		r = lq_asn_write(asn, "parent", (char*)&c, 1);
		if (r != ERR_OK) {
			return r;
		}
	} else {
		r = state_digest(cert, cert->parent_hash, 1);
		if (r != ERR_OK) {
			//return asn_except(&item, r);
			lq_asn_free(asn);
			return r;
		}
		c = LQ_DIGEST_LEN;
//		r = asn1_write_value(item, "Cert.parent", cert->parent_hash, c);
//		if (r != ASN1_SUCCESS) {
//			return asn_except(&item, ERR_WRITE);
//		}
		r = lq_asn_write(asn, "parent", cert->parent_hash, c);
		if (r != ERR_OK) {
			return r;
		}
	}

	*out_len = mx;
//	r = asn1_der_coding(item, "Cert", out, (int*)out_len, err);
//	if (r != ASN1_SUCCESS) {
//		return asn_except(&item, ERR_ENCODING);
//	}
	r = lq_asn_out(asn, out, out_len);
	if (r != ERR_OK) {
		return r;
	}

//	r = asn1_delete_structure(&item);
//	if (r != ASN1_SUCCESS) {
//		return ERR_FAIL;
//	}
	lq_asn_free(asn);

	return ERR_OK;
}

/**
 * \todo pubkey is copied to signature from message, to prevent a double-free. Wastes up to 2x sig bytes.
 *
 */
int lq_certificate_deserialize(LQCert **cert, LQResolve *resolve, char *in, size_t in_len) {
	int r;
	size_t c;
	char err[LQ_ERRSIZE];
	char tmp[LQ_BLOCKSIZE];
	//asn1_node item;
	LQASN *asn;
	LQCert *p;

//	lq_zero(&item, sizeof(item));
	
//	r = asn1_create_element(asn, "Qaeda.Cert", &item);
//	if (r != ASN1_SUCCESS) {
//		return ERR_READ;
//	}
//	r = asn1_der_decoding(&item, in, in_len, err);
//	if (r != ASN1_SUCCESS) {
//		return asn_except(&item, ERR_ENCODING);
//	}
	asn = lq_asn_parse("Cert", in, in_len);
	if (asn == NULL) {
		return ERR_READ;
	}

	c = LQ_CERT_DOMAIN_LEN;
//	r = asn1_read_value(item, "domain", tmp, &c);
//	if (r != ASN1_SUCCESS) {
//		return asn_except(&item, ERR_READ);
//	}
	r = lq_asn_read(asn, "domain", tmp, &c);
	if (r != ERR_OK) {
		return r;
	}

	*cert = lq_certificate_new(NULL);
	p = *cert;
	lq_certificate_set_domain(p, tmp);

	c = LQ_BLOCKSIZE;
//	r = asn1_read_value(item, "request", tmp, &c);
//	if (r != ASN1_SUCCESS) {
//		return asn_except(&item, ERR_READ);
//	}
	r = lq_asn_read(asn, "request", tmp, &c);
	if (r != ERR_OK) {
		return r;
	}
	r = lq_msg_deserialize(&p->request, resolve, tmp, c);
	if (r != ERR_OK) {
		//return asn_except(&item, r);
		lq_asn_free(asn);
		return r;
	}
	if (p->request != NULL) {
		c = LQ_BLOCKSIZE;
//		r = asn1_read_value(item, "request_sig", tmp, &c);
//		if (r != ASN1_SUCCESS) {
//			lq_msg_free(p->request);
//			return asn_except(&item, ERR_READ);
//		}
		r = lq_asn_read(asn, "request_sig", tmp, &c);
		if (r != ERR_OK) {
			lq_msg_free(p->request);
			return r;
		}
		if (c > 0) {
			p->request_sig = lq_signature_from_bytes(tmp, c, p->request->pubkey);
		}
	}

	c = LQ_BLOCKSIZE;
//	r = asn1_read_value(item, "response", tmp, &c);
//	if (r != ASN1_SUCCESS) {
//		lq_signature_free(p->request_sig);
//		lq_msg_free(p->request);
//		return asn_except(&item, ERR_READ);
//	}
	r = lq_asn_read(asn, "response", tmp, &c);
	if (r != ERR_OK) {
		lq_signature_free(p->request_sig);
		lq_msg_free(p->request);
		return r;
	}

	r = lq_msg_deserialize(&p->response, resolve, tmp, c);
	if (r != ERR_OK) {
		lq_signature_free(p->request_sig);
		lq_msg_free(p->request);
		//return asn_except(&item, r);
		lq_asn_free(asn);
		return r;
	}
	if (p->response != NULL) {
		c = LQ_BLOCKSIZE;
//		r = asn1_read_value(item, "response_sig", tmp, &c);
//		if (r != ASN1_SUCCESS) {
//			lq_msg_free(p->response);
//			lq_signature_free(p->request_sig);
//			lq_msg_free(p->request);
//			return asn_except(&item, ERR_READ);
//		}
		r = lq_asn_read(asn, "response_sig", tmp, &c);
		if (r != ERR_OK) {
			lq_msg_free(p->response);
			lq_signature_free(p->request_sig);
			lq_msg_free(p->request);
			return r;
		}

		if (c > 0) {
			p->response_sig = lq_signature_from_bytes(tmp, c, p->response->pubkey);
		}
	}

	c = 4096;
//	r = asn1_read_value(item, "parent", tmp, &c);
//	if (r != ASN1_SUCCESS) {
//		lq_signature_free(p->response_sig);
//		lq_msg_free(p->response);
//		lq_signature_free(p->request_sig);
//		lq_msg_free(p->request);
//		return asn_except(&item, ERR_READ);
//	}
	r = lq_asn_read(asn, "parent", tmp, &c);
	if (r != ERR_OK) {
		lq_signature_free(p->response_sig);
		lq_msg_free(p->response);
		lq_signature_free(p->request_sig);
		lq_msg_free(p->request);
		return r;
	}

	p->parent = NULL;
	if (c == 1) {
		lq_zero(p->parent_hash, LQ_DIGEST_LEN);
	} else {
		lq_cpy(p->parent_hash, tmp, LQ_DIGEST_LEN);
	}
	// \todo render parent if set


	lq_asn_free(asn);
//	r = asn1_delete_structure(&item);
//	if (r != ASN1_SUCCESS) {
//		return ERR_FAIL;
//	}

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
