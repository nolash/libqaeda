#include <string.h>
#include <stdlib.h>
#include <stddef.h>

void* lq_alloc(size_t bytes) {
	return malloc(bytes);
}

void lq_free(void *o) {
	free(o);
}

void* lq_cpy(void *dst, const void *src, size_t len) {
	return memcpy(dst, src, len);
}

void* lq_set(void *dst, const char b, size_t len) {
	return memset(dst, (int)b, len);
}
