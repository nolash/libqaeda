#ifndef LIBQAEDA_MSG_H_
#define LIBQAEDA_MSG_H_

#include <stddef.h>
#include <time.h>

#include "lq/crypto.h"
#include "lq/store.h"

enum lq_msgstate_e {
	LQ_MSG_INIT = 1,
	LQ_MSG_RESOLVED = 2,
	LQ_MSG_LITERAL = 4,
};

/**
 * \struct LQMsg
 *
 * \brief Represents a message that is used as part of certificate as request or response.
 *
 * \see lq_msg_t 
 */
struct lq_msg_t {
	char state; ///< Message resolution state
	char *data; ///< Arbitrary data constituting the message.
	size_t len; ///< Length of arbitrary data.
	struct timespec time; ///< Nanosecond timestamp of when the message was created.
	LQPubKey *pubkey; ///< Public key authoring the message. Must be checked against any private key calculating a signature over it.
};
typedef struct lq_msg_t LQMsg;

/**
 * \brief Instantiate a new message object.
 *
 * \param[in] Message data. Data will be copied.
 * \param[in] Length of message data.
 * \return Instantiated message object. It is the caller's responsibility to free to object.
 * \see lq_msg_free
 */
LQMsg* lq_msg_new(const char *msg_data, size_t msg_len);

/**
 * \brief Calculate a signature over the message. Uses default salt value.
 *
 * \param[in] Message to sign.
 * \param[in] Private key to sign with.
 * \param[in] Salt data to secure signature with. Set to NULL if salt is not to be used.
 * \return Signature object. Object will be NULL if signature calculation failed. It is the caller's responsibility to free the signature object.
 *
 * \see lq_signature_free
 */
LQSig* lq_msg_sign(LQMsg *msg, LQPrivKey *pk, const char *salt);

/**
 * \brief Calculate a signature over the message with a specified salt value. The salt value length must be LQ_SALT_LEN.
 *
 * \param[in] Message to sign.
 * \param[in] Private key to sign with.
 * \param[in] Salt data to secure signature with. Set to NULL if salt is not to be used.
 * \param[in] Extra data to prefix message data with when calculating digest. If set to NULL, only message data will be used in digest.
 * \param[in] Length of extra data. Ignored if extra data is NULL.
 * \return Signature object. Object will be NULL if signature calculation failed. It is the caller's responsibility to free the signature object.
 *
 * \see lq_signature_free
 */
LQSig* lq_msg_sign_extra(LQMsg *msg, LQPrivKey *pk, const char *salt, const char *extra, size_t extra_len);

/**
 * \brief Verify the signature over the message with specified salt value. The salt value length must be LQ_SALT_LEN.
 *
 * The message will be verified against the public key defined in the message structure.
 *
 * \param[in] Message to verify. (Must have the publickey member set).
 * \param[in] Signature to verify.
 * \param[in] Salt data that was used when calculating signature. Set to NULL if salt is not to be used. 
 * \param[in] Extra data to prefix message data with when calculating digest. If set to NULL, only message data will be used in digest.
 * \param[in] Length of extra data. Ignored if extra data is NULL.
 * \return ERR_OK on valid signature, ERR_NONSENSE if publickey missing. Any other value indicates failure.
 *
 * \see lq_signature_free
 */
int lq_msg_verify_extra(LQMsg *msg, LQSig *sig, const char *salt, const char *extra, size_t extra_len);

/**
 * \brief Serialize message data payload for inclusion in certificate.
 *
 * \param[in] Message to serialize.
 * \param[in] Store implementations to use for storing serialized message data. If NULL, content will not be stored in resolver.
 * \param[out] Output buffer.
 * \param[out] Value behind pointer must contain the capacity of output buffer. Will be overwritten with the actual number of bytes written.
 * \return ERR_OK if serialization is successful, or:
 * 	* ERR_INIT if the serialization object couldn't be instantiated.
 * 	* ERR_OVERFLOW if output exceeded the available space in output buffer.
 * 	* ERR_WRITE if serialization of an element failed.
 * 	* ERR_ENCODING if generating the final serialization string failed.
 */
int lq_msg_serialize(LQMsg *msg, LQResolve *resolve, char *out, size_t *out_len);

/**
 * \brief Deserialize message data payload from certificate.
 *
 * \param[out] Pointer to instantiated message. It is the caller's responsibility to free the message object.
 * \param[in] Store implementations to use for resolving content key from deserialized message data. If NULL, content will not be resolved.
 * \param[in] Serialized data.
 * \param[in] Length of serialized data.
 * \return ERR_OK if deserialization is successful, or:
 * 	* ERR_INIT if the serialization object couldn't be instantiated.
 * 	* ERR_READ if deserialization of an element failed.
 * 	* ERR_ENCODING if interpretation of the serialized data failed.
 *
 * \see lq_msg_free
 */
int lq_msg_deserialize(LQMsg **msg, LQResolve *resolve, const char *in, size_t in_len);

/**
 * \brief Mark message content as literal.
 *
 * In this case, the data of the message will be stored directly, instead of its hash.
 *
 * \param[in] Message to manipulate.
 * \return ERR_OK if succesfully set, ERR_NOOP if already set.
 */
int lq_msg_literal(LQMsg *msg);

/**
 * \brief Free an instantiated message.
 *
 * \param[in] Message to free.
 */
void lq_msg_free(LQMsg *msg);

/**
 * \brief Serialize message content.
 *
 * \param[in] Content to serialize.
 * \param[in] Length of content
 * \param[out] Output buffer
 * \param[in/out] Length of output buffer, will be overwritten by length of serialized data.
 *
 * \return ERR_OK on success.
 *
 * \see lq_msg_serialize
 */
int lq_attach_serialize(const char *in, size_t in_len, char *out, size_t *out_len);

#endif // LIBQAEDA_MSG_H_
