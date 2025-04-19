#ifndef LIBQAEDA_ENVELOPE_H_
#define LIBQAEDA_ENVELOPE_H_

#include <stddef.h>
#include <lq/cert.h>

/***
 * \brief Encapsulates a single data blob, referenced by message digest, to be bundled with the envelope.
 */
struct lq_attach {
	char *data; ///< Data to bundle.
	size_t len; ///< Length of data to bundle.
	struct lq_attach *next; ///< Next attachment to bundle, linked-list.
};

/**
 * \brief Structure used for end-user transport of certificate.
 *
 * The envelope enables bundling of the message data referenced by the message hashes. If the message is not literal, then the interpreter of the certificate will have to resolve the contents through other means.
 */
struct lq_envelope {
	int hint; ///< Application level hint to assist in interpreting contents of envelope.
	LQCert *cert; ///< Certificate to bundle.
	struct lq_attach *attach_start; ///< Pointer to first attachment to include.
	struct lq_attach *attach_cur; ///< Pointer to next position to add a new attachment.
};
typedef struct lq_envelope LQEnvelope;


/**
 * \brief Allocate a new attachment object
 *
 *
 * \param[in] Certificate to bundle.
 * \param[in] Application level interpretation hint.
 * \return Newly allocated LQEnvelope object, NULL if failed.
 *
 * \see lq_envelope_free
 */
LQEnvelope *lq_envelope_new(LQCert *cert, int hint);

/**
 * \brief Add a single data blob to the bundle.
 *
 * \param[in] Envelope to add data to.
 * \param[in] Buffer containing the data to add.
 * \param[in] Length of data to add.
 * \return ERR_OK on success. 
 */
int lq_envelope_attach(LQEnvelope *env, const char *data, size_t data_len);


/**
 * \brief Serialize envelope data for transport.
 *
 * \param[in] Envelope to serialize.
 * \param[in] Store implementations to use for resolving content key from deserialized message and certificate data. If NULL, content will not be resolved.
 * \param[out] Data buffer where serialized data will be written.
 * \param[in/out] Length of data buffer. Will be overwritten with the length of the written data.
 * \return ERR_OK if serialization is successful, or:
 * 	* ERR_INIT if the serialization object couldn't be instantiated.
 * 	* ERR_OVERFLOW if output exceeded the available space in output buffer.
 * 	* ERR_WRITE if serialization of an element failed.
 * 	* ERR_ENCODING if generating the final serialization string failed.
 *
 * \see lq_certificate_serialize
 */
int lq_envelope_serialize(LQEnvelope *env, LQResolve *resolve, char *data, size_t *data_len);

/**
 * \brief Deserialize certificate data payload from storage or transport.
 *
 * \param[out] Pointer where envelope will be instantiated. It is the caller's responsibility to free the envelope object.
 * \param[in] Store implementations to use for resolving content key from deserialized message and certificate data. If NULL, content will not be resolved.
 * \param[in] Serialized data.
 * \param[in] Length of serialized data.
 * \return ERR_OK if deserialization is successful, or:
 * 	* ERR_INIT if the serialization object couldn't be instantiated.
 * 	* ERR_READ if deserialization of an element failed.
 * 	* ERR_ENCODING if interpretation of the serialized data failed.
 *
 * \see lq_certificate_deserialize
 * \see lq_envelope_free
 */

int lq_envelope_deserialize(LQEnvelope **env, LQResolve *resolve, const char *data, size_t data_len);

/**
 * \brief Free an instantiated envelope.
 *
 * For convenience, this will also free the associated certificate.
 *
 * \param[in] Envelope to free.
 */
void lq_envelope_free(LQEnvelope *env);

#endif // LIBQAEDA_ENVELOPE_H_
