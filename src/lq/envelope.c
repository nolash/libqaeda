#include <stddef.h>
#include <stdio.h>

#include <endian.h>
#include <llog.h>
#include <lq/envelope.h>
#include <lq/cert.h>
#include <lq/mem.h>
#include <lq/err.h>
#include <lq/asn.h>
#include <debug.h>


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

	return env;
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

int lq_envelope_serialize(LQEnvelope *env, LQResolve *resolve, char *out, size_t *out_len) {
	size_t c;
	int mx;
	int r;
	int hint;
	char err[LQ_ERRSIZE];
	char buf[LQ_BLOCKSIZE];
	LQASN *asn;

	mx = *out_len;
	*out_len = 0;
	asn = lq_asn_new("Envelope");
	if (asn == NULL) {
		return ERR_WRITE;
	}


	hint = env->hint;
	r = to_endian(TO_ENDIAN_BIG, sizeof(int), &hint);
	if (r) {
		lq_asn_free(asn);
		return ERR_BYTEORDER;
	}
	c = sizeof(int);
	r = lq_asn_write(asn, "hint", (char*)&hint, c);
	if (r != ERR_OK) {
		return r;
	}

	c = mx - sizeof(int);
	r = lq_certificate_serialize(env->cert, resolve, buf, &c);
	if (r != ERR_OK) {
		lq_asn_free(asn);
		return r;
	}
	*out_len += c;
	if (*out_len > mx) {
		lq_asn_free(asn);
		return ERR_OVERFLOW;
	}
	r = lq_asn_write(asn, "cert", buf, c);
	if (r != ERR_OK) {
		lq_asn_free(asn);
		return r;
	}


	while(1) {
		c = LQ_BLOCKSIZE;
		r = lq_envelope_get(env, buf, &c);
		if (r) {
			break;
		}

		r = lq_asn_write(asn, "attach", "NEW", 1);
		if (r != ERR_OK) {
			lq_asn_free(asn);
			return ERR_WRITE;
		}
		r = lq_asn_write(asn, "attach.?LAST", buf, c);
		if (r != ERR_OK) {
			lq_asn_free(asn);
			return ERR_WRITE;
		}
	}	

	*out_len = mx;
	r = lq_asn_out(asn, out, out_len);
	if (r != ERR_OK) {
		lq_asn_free(asn);
		return r;
	}

	lq_asn_free(asn);

	return ERR_OK;
}

int lq_envelope_deserialize(LQEnvelope **env, LQResolve *resolve, const char *in, size_t in_len) {
	size_t c;
	int r;
	int i;
	char err[LQ_ERRSIZE];
	char tmp[LQ_BLOCKSIZE];
	char node_seq_name[32];
	int hint;
	char *p;
	LQCert *cert;
	LQASN *asn;

	asn = lq_asn_parse("Envelope", in, in_len);
	if (asn == NULL) {
		return ERR_READ;
	}

	hint = 0;
	c = sizeof(int);
	r = lq_asn_read(asn, "hint", (char*)&hint, &c);
	if (r != ERR_OK) {
		lq_asn_free(asn);
		return r;
	}

	hint <<= ((sizeof(int) - c) * 8);
	if (is_le()) {
		flip_endian(sizeof(int), (char*)(&hint));
	}

	c = LQ_BLOCKSIZE;
	r = lq_asn_read(asn, "cert", tmp, &c);
	if (r != ERR_OK) {
		lq_asn_free(asn);
		return r;
	}
	r = lq_certificate_deserialize(&cert, resolve, tmp, c);
	if (r != ERR_OK) {
		lq_asn_free(asn);
		return r;
	}

	*env = lq_envelope_new(cert, hint);

	i = 0;
	while(++i) {
		c = LQ_BLOCKSIZE;
		sprintf(node_seq_name, "attach.?%i", i);
		r = lq_asn_read(asn, node_seq_name, tmp, &c);
		if (r != ERR_OK) {
			break;
		}
		r = lq_envelope_attach(*env, tmp, c);
		if (r != ERR_OK) {
			lq_envelope_free(*env);
			lq_asn_free(asn);
			return ERR_FAIL;
		}
	}

	lq_asn_free(asn);

	return ERR_OK;
}

void lq_envelope_free(LQEnvelope *env) {
	lq_attach_free(env->attach_start);
	lq_certificate_free(env->cert);
	lq_free(env);
}
