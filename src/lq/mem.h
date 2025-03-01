#ifndef LIBQAEDA_MEM_H_
#define LIBQAEDA_MEM_H_

#include <stddef.h>

void* lq_alloc(size_t bytes);
void lq_free(void *o);
void* lq_cpy(void *dst, void *src, size_t len);
void* lq_set(void *dst, char b, size_t len);

#endif // LIBQAEDA_MEM_H_
