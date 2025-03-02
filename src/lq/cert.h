#ifndef LIBQAEDA_CERT_H_
#define LIBQAEDA_CERT_H_

#include <stddef.h>

#include "lq/crypto.h"
#include "lq/msg.h"
#include "lq/ctx.h"

#ifndef LQ_CERT_DOMAIN_LEN
#define LQ_CERT_DOMAIN_LEN 8
#endif

typedef struct lq_certificate_t LQCert;
struct lq_certificate_t {
	LQCert *parent;
	char domain[LQ_CERT_DOMAIN_LEN];
	LQMsg *request;
	LQSig *request_sig;
	LQMsg *response;
	LQSig *response_sig;
	LQCtx *ctx;
};

LQCert* lq_certificate_new(LQCert *parent, LQCtx *ctx, LQMsg *req, LQMsg *rsp);
int lq_certificate_serialize(LQCert *cert, char *out, size_t *out_len);
int lq_certificate_deserialize(LQCert *cert, char *in, size_t in_len);
int lq_certificate_verify(LQCert *cert);
void lq_certificate_free(LQCert *cert);

#endif // LIBQAEDA_CERT_H_
