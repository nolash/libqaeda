#ifndef LIBQAEDA_CERT_H_
#define LIBQAEDA_CERT_H_

#include <stddef.h>

#include "lq/msg.h"
#include "lq/ctx.h"

typedef struct lq_certificate_t LQCert;
struct lq_certificate_t {
	LQCert *parent;
	LQMsg *request;
	LQMsg *response;
	LQCtx *ctx;
};

int lq_certificate_sign_request(LQCert *cert, struct LQPrivKey *pk);
int lq_certificate_sign_response(LQCert *cert, struct LQPrivKey *pk);
int lq_certificate_serialize(LQCert *cert, char *data, size_t *data_len);
int lq_certificate_deserialize(LQCert *cert, char *data, size_t data_len);
int lq_certificate_verify(LQCert *cert);

#endif // LIBQAEDA_CERT_H_
