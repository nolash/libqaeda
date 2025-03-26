#include <string.h>
#include <stdlib.h>
#include <stddef.h>

void* lq_alloc(size_t bytes) {
	return malloc(bytes);
}

void lq_free(void *o) {
	free(o);
}

int lq_cmp(const void *dst, const void *src, size_t len) {
	return memcmp(dst, src, len);
}

void* lq_cpy(void *dst, const void *src, size_t len) {
	return memcpy(dst, src, len);
}

void* lq_set(void *dst, const char b, size_t len) {
	return memset(dst, (int)b, len);
}

void* lq_zero(void *dst, size_t len) {
	return lq_set(dst, 0, len);
}
