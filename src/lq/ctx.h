#ifndef LIBQAEDA_CTX_H_
#define LIBQAEDA_CTX_H_

#define CTX_BITS 64

struct lq_ctx_t {
	char *flag;
};
typedef struct lq_ctx_t LQCtx;

LQCtx* lq_ctx_new();
void lq_ctx_free(LQCtx *ctx);

#endif // LIBQAEDA_CTX_H_
