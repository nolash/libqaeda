#ifndef LIBQAEDA_MSG_H_
#define LIBQAEDA_MSG_H_

#include <stddef.h>
#include <time.h>

#include "lq/crypto.h"

/***
 * @struct LQMsg
 * @brief Represents a message that is used as part of certificate as request or response.
 * @var LQMsg::data
 * Arbitrary data constituting the message.
 * @var LQMsg::len
 * Length of arbitrary data.
 * @var LQMsg::time
 * Nanosecond timestamp of when the message was created.
 * @var LQMsg::pubkey
 * Public key authoring the message. Must be checked against any private key calculating a signature over it.
 */
struct lq_msg_t {
	char *data;
	size_t len;
	struct timespec time;
	LQPubKey *pubkey;
};
typedef struct lq_msg_t LQMsg;

/***
 * @brief Instantiate a new message object.
 * @param[in] Message data. Data will be copied.
 * @param[in] Length of message data.
 * @return Instantiated message object. It is the caller's responsibility to free to object.
 * @see lq_msg_free
 */
LQMsg* lq_msg_new(const char *msg_data, size_t msg_len);

/***
 * @brief Calculate a signature over the message. Uses default salt value.
 * @param[in] Message to sign.
 * @param[in] Private key to sign with.
 * @param[in] Salt data to secure signature with. Set to NULL if salt is not to be used.
 * @return Signature object. Object will be NULL if signature calculation failed. It is the caller's responsibility to free the signature object.
 * @see lq_signature_free
 */
LQSig* lq_msg_sign(LQMsg *msg, LQPrivKey *pk, const char *salt);

/***
 * @brief Calculate a signature over the message with a specified salt value. The salt value length must be LQ_SALT_LEN.
 * @param[in] Message to sign.
 * @param[in] Private key to sign with.
 * @param[in] Salt data to secure signature with. Set to NULL if salt is not to be used.
 * @param[in] Extra data to prefix message data with when calculating digest. If set to NULL, only message data will be used in digest.
 * @param[in] Length of extra data. Ignored if extra data is NULL.
 * @return Signature object. Object will be NULL if signature calculation failed. It is the caller's responsibility to free the signature object.
 * @see lq_signature_free
 */
LQSig* lq_msg_sign_extra(LQMsg *msg, LQPrivKey *pk, const char *salt, const char *extra, size_t extra_len);

/***
 * @brief Serialize message data payload for inclusion in certificate.
 * @param[in] Message to serialize.
 * @param[out] Output buffer.
 * @param[out] Value behind pointer must contain the capacity of output buffer. Will be overwritten with the actual number of bytes written.
 * @return ERR_OK if serialization is successful, or:
 * 	* ERR_INIT if the serialization object couldn't be instantiated.
 * 	* ERR_OVERFLOW if output exceeded the available space in output buffer.
 * 	* ERR_WRITE if serialization of an element failed.
 * 	* ERR_ENCODING if generating the final serialization string failed.
 */
int lq_msg_serialize(LQMsg *msg, char *out, size_t *out_len);

/***
 * @brief Deserialize message data payload from certificate.
 * @param[out] Pointer to instantiated message. It is the caller's responsibility to free the message object.
 * @param[in] Serialized data.
 * @param[in] Length of serialized data.
 * @return ERR_OK if deserialization is successful, or:
 * 	* ERR_INIT if the serialization object couldn't be instantiated.
 * 	* ERR_READ if deserialization of an element failed.
 * 	* ERR_ENCODING if interpretation of the serialized data failed.
 * @see lq_msg_free
 */
int lq_msg_deserialize(LQMsg **msg, const char *in, size_t in_len);

/***
 * @brief Free an instantiated message.
 * @param[in] Message to free.
 */
void lq_msg_free(LQMsg *msg);

#endif // LIBQAEDA_MSG_H_
