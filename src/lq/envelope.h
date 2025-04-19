#ifndef LIBQAEDA_ENVELOPE_H_
#define LIBQAEDA_ENVELOPE_H_

#include <stddef.h>
#include <lq/cert.h>

struct lq_attach {
	char *data;
	size_t len;
	struct lq_attach *next;
};

struct lq_envelope {
	int hint;
	LQCert *cert;
	struct lq_attach *attach_start;
	struct lq_attach *attach_cur;
};
typedef struct lq_envelope LQEnvelope;


/**
 * \brief Set up a new attachment object
 *
 *
 */
LQEnvelope *lq_envelope_new(LQCert *cert, int hint);

/**
 *
 * \return ERR_OK on success. 
 */
int lq_envelope_attach(LQEnvelope *env, const char *data, size_t data_len);
int lq_envelope_serialize(LQEnvelope *env, const char *data, size_t *data_len);
int lq_envelope_deserialize(LQEnvelope **env, const char *data, size_t data_len);
void lq_envelope_free(LQEnvelope *env);

#endif // LIBQAEDA_ENVELOPE_H_
