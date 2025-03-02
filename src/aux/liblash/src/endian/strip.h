#ifndef LASH_BYTES_H_
#define LASH_BYTES_H_

/**
 * strip zero value zeros from a big-endian integer array
 *
 * \param value integer data to strip zeros from.
 * \parmm len pointer to length of input integer data. Length of stripped integer will be written here.
 * \return pointer to position in buffer containing the stripped integer data.
 *
 */
char* strip_be(char *value, size_t *len);
/**
 * expand a truncated signed big-endian integer to full bitsize
 *
 * \param in integer data to expand.
 * \param in_len length of input integer.
 * \param out output buffer where expanded integer will be written.
 * \param out_len output buffer capacity.
 * \return 0 if successfully written, 1 on any failure.
 *
 */
int strap_be(const char *in, size_t in_len, char *out, size_t out_len);

#endif
