#include "lq/ctx.h"
#include "lq/mem.h"

LQCtx* lq_ctx_new() {
	LQCtx *ctx;

	ctx = lq_alloc(sizeof(LQCtx));
	return ctx;
}

void lq_ctx_free(LQCtx *ctx) {
	lq_free((void*)ctx);
}
