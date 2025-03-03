#ifndef LIBQAEDA_MEM_H_
#define LIBQAEDA_MEM_H_

#include <stddef.h>

/**
 * @brief Allocate heap memory.
 *
 * @param[in] Number of memory bytes to allocate.
 * @return Pointer to allocated memory. Returns NULL if allocation has failed.
 */
void* lq_alloc(size_t bytes);

/**
 * @brief Free a memory pointer.
 *
 * @param[in] Pointer to free.
 */
void lq_free(void *o);

/**
 * @brief Copy memory region.
 *
 * @param[out] Destination memory.
 * @param[in] Source memory.
 * @param[in] Number of bytes to copy.
 * @return Pointer to written memory.
 */
void* lq_cpy(void *dst, const void *src, size_t len);

/**
 *
 * @brief Fill memory region with value.
 *
 * @param[out] Destination memory.
 * @param[in] Value to write.
 * @param[in] Number of bytes to write.
 * @return Pointer to written memory.
 */
void* lq_set(void *dst, const char b, size_t len);

#endif // LIBQAEDA_MEM_H_
