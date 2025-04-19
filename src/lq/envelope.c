#include <stddef.h>

#include <libtasn1.h>
#include <llog.h>
#include <lq/envelope.h>
#include <lq/cert.h>
#include <lq/mem.h>
#include <lq/err.h>
#include <debug.h>


extern asn1_node asn;

static struct lq_attach *lq_attach_new() {
	struct lq_attach *o;
       
	o = lq_alloc(sizeof(struct lq_attach));
	if (o == NULL) {
		return o;
	}
	lq_zero(o, sizeof(struct lq_attach));
	return o;
}

static struct lq_attach *lq_attach_add(struct lq_attach *attach, const char *data, size_t data_len) {
	attach->len = data_len;
	attach->data = lq_alloc(data_len);
	lq_cpy(attach->data, data, data_len);
	attach->next = lq_alloc(sizeof(struct lq_attach));
	lq_zero(attach->next, sizeof(struct lq_attach));
	return attach->next;
}

static int lq_envelope_get(struct lq_envelope *env, char *out, size_t *out_len) {
	struct lq_attach *attach;

	attach = env->attach_start;
	if (attach == NULL) {
		return ERR_NOENT;
	}
	lq_cpy(out, attach->data, attach->len);
	*out_len = attach->len;
	lq_free(attach->data);
	if (attach->next == NULL) {
		return ERR_NOENT;
	}
	env->attach_start = attach->next;
	lq_free(attach);
	return ERR_OK;
}

static void lq_attach_free(struct lq_attach *attach) {
	if (attach->next != NULL) {
		lq_attach_free(attach->next);
	}
	lq_free(attach->data);
	lq_free(attach);
}

LQEnvelope *lq_envelope_new(LQCert *cert, int hint) {
	LQEnvelope *env;

	env = lq_alloc(sizeof(LQEnvelope));
	env->hint = hint;
	env->cert = cert;
	env->attach_start = lq_attach_new();
	env->attach_cur = env->attach_start;
}

int lq_envelope_attach(LQEnvelope *env, const char *data, size_t data_len) {
	struct lq_attach *attach;

	attach = lq_attach_add(env->attach_cur, data, data_len);
	if (attach == NULL) {
		return ERR_FAIL;
	}
	env->attach_cur = attach;

	return ERR_OK;
}

// TODO: DRY
static int asn_except(asn1_node *node, int err) {
	int r;

	r = asn1_delete_structure(node);
	if (r != ASN1_SUCCESS) {
		debug_logerr(LLOG_ERROR, ERR_FAIL, asn1_strerror(err));
	}

	return err;
}

int lq_envelope_serialize(LQEnvelope *env, LQResolve *resolve, const char *out, size_t *out_len) {
	size_t c;
	int mx;
	int r;
	char err[LQ_ERRSIZE];
	char buf[LQ_BLOCKSIZE];
	char node_seq_name[64];
	asn1_node item;

	mx = *out_len;
	*out_len = 0;
	lq_zero(&item, sizeof(item));

	r = asn1_create_element(asn, "Qaeda", &item);
	if (r != ASN1_SUCCESS) {
		return ERR_READ;
	}

	c = sizeof(int);
	r = asn1_write_value(item, "Envelope.hint", &env->hint, c);
	if (r != ASN1_SUCCESS) {
		return asn_except(&item, ERR_WRITE);
	}

	c = mx - sizeof(int);
	r = lq_certificate_serialize(env->cert, resolve, buf, &c);
	if (r != ERR_OK) {
		return asn_except(&item, r);
	}
	*out_len += c;
	if (*out_len > mx) {
		return asn_except(&item, ERR_OVERFLOW);
	}
	r = asn1_write_value(item, "Envelope.cert", buf, c);
	if (r != ASN1_SUCCESS) {
		return asn_except(&item, ERR_WRITE);
	}

	while(1) {
		c = LQ_BLOCKSIZE;
		r = lq_envelope_get(env, buf, &c);
		if (r) {
			break;
		}
		r = asn1_write_value(item, "Envelope.attach", "NEW", 1);
		if (r != ASN1_SUCCESS) {
			return asn_except(&item, ERR_WRITE);
		}
		r = asn1_write_value(item, "Envelope.attach.?LAST", buf, c);
		if (r != ASN1_SUCCESS) {
			return asn_except(&item, ERR_WRITE);
		}
	}	

	*out_len = mx;
	r = asn1_der_coding(item, "Envelope", out, (int*)out_len, err);
	if (r != ASN1_SUCCESS) {
		return asn_except(&item, ERR_ENCODING);
	}

	r = asn1_delete_structure(&item);
	if (r != ASN1_SUCCESS) {
		return ERR_FAIL;
	}
}

void lq_envelope_free(LQEnvelope *env) {
	lq_attach_free(env->attach_start);
	lq_certificate_free(env->cert);
	lq_free(env);
}
