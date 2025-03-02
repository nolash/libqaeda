#ifndef LIBQAEDA_CERT_H_
#define LIBQAEDA_CERT_H_

#include <stddef.h>

#include "lq/crypto.h"
#include "lq/msg.h"
#include "lq/ctx.h"

#ifndef LQ_CERT_DOMAIN_LEN
#define LQ_CERT_DOMAIN_LEN 8
#endif

/***
 * @struct LQCert
 * @brief A certificate is a counter-signed piece of arbitrary data within a designated domain. It may or may not be linked to a previous certificate.
 * @var LQCert::parent
 * Link to previous certificate. Optional. Set to NULL if no link exists.
 * @var LQCert::domain
 * Domain data is used by application data to evaluate whether a record is relevant for it or not.
 * @var LQCert::request
 * A request message encapsulates an arbitrary string of data that should be confirmed by a responder.
 * @var LQCert::request_sig
 * Signature over a request message and the linked certificate. If the linked certificate is NULL, the certificate data used in the signature with be a LQ_DIGEST_LEN string with all bytes set to 0.
 * @var LQCert::response
 * A response message encapsulates an arbitrary string of data that confirms a request. This field must be NULL unless a signed requests exists.
 * @var LQCert::response_sig
 * Signature over a response message. This field must be NULL unless a response message is set. The signature is calculated over both the response and the signed request.
 * @var LQCert::ctx
 * Context reflecting the behavior of state, validation and serialization of the certificate.
 */
typedef struct lq_certificate_t LQCert;
struct lq_certificate_t {
	char domain[LQ_CERT_DOMAIN_LEN];
	LQMsg *request;
	LQSig *request_sig;
	LQMsg *response;
	LQSig *response_sig;
	LQCtx ctx;
	LQCert *parent;
	char parent_hash[LQ_DIGEST_LEN];
};

/***
 * @brief Create a new certificate.
 * @param[in] Previous certificate to link to.
 * @param[in] Context to control behavior of certificate processing. If NULL, default behavior will be used.
 * @param[in] Request message.
 * @param[in] Response message.
 * @return The allocated certificate object. It is the caller's responsibility to free the object.
 * @todo request and response message does not make sense to set without option to set signature, factor out to separate functions.
 * @see lq_certificate_free
 */
LQCert* lq_certificate_new(LQCert *parent, LQCtx *ctx, LQMsg *req, LQMsg *rsp);

/***
 * @brief Set the domain of the certificate. If not set, the default domain value will be used, which is LQ_DOMAIN_LEN bytes set to 0.
 * @param[in] Instantiated certificate to set domain on.
 * @param[in] Domain data. Must be LQ_DOMAIN_LEN bytes long.
 */
void lq_certificate_set_domain(LQCert *cert, const char *domain);

/***
 * @brief Sign the next pending message in the certificate. If the request message is set but not signed, the request message will be signed. If the response message is set but not signed, the response message will be signed. The limitations described in the struct declaration apply.
 *
 * Depending on the state of the certificate, additional data will be prepended to the message before calculating the digest, where <value> means a required value, [value] means and optional value, and "|" means concatenate.
 *
 * <domain> | [ parent | ] [ request_signature | ] [ response_signature | ]
 *
 * If the certificate is linked to another certificate, then the digest of that certificate will be calculated and used as the "parent" value. Note that a linked certificate must be finalized, meaning it must have a valid response signature.
 *
 * If the certificate has the request_signature it will be used as the request_signature value.
 *
 * If the certificate has the response_signature it will be used as the response_signature value. The response_signature may not exist without the request_signature.
 *
 * @param[in] Instantiated certificate to perform signature on.
 * @param[in] Private key to use for signature.
 * @return ERR_OK on successful signature, or:
 * 	* ERR_REQUEST if request has already been signed  (and response is not set)
 * 	* ERR_RESPONSE if response has already been signed.
 * 	* ERR_ENCODING if calculateing the signature failed.
 * 	* ERR_INIT if no message eligible for signature exists.
 */
int lq_certificate_sign(LQCert *cert, LQPrivKey *pk);

/***
 * @brief Serialize certificate data payload for storage and transport.
 * @param[in] Certificate to serialize
 * @param[out] Buffer to write data to.
 * @param[out] Value behind pointer must contain the capacity of the output buffer. Will be overwritten with the actual number of bytes written.
 * @return ERR_OK if serialization is successful, or:
 * 	* ERR_INIT if the serialization object couldn't be instantiated.
 * 	* ERR_OVERFLOW if output exceeded the available space in output buffer.
 * 	* ERR_WRITE if serialization of an element failed.
 * 	* ERR_ENCODING if generating the final serialization string failed.
 */
int lq_certificate_serialize(LQCert *cert, char *out, size_t *out_len);

/***
 * @brief Deserialize certificate data payload from storage or transport.
 * @param[out] Pointer to instantiated certificate. It is the caller's responsibility to free the certificate object.
 * @param[in] Serialized data.
 * @param[in] Length of serialized data.
 * @return ERR_OK if deserialization is successful, or:
 * 	* ERR_INIT if the serialization object couldn't be instantiated.
 * 	* ERR_READ if deserialization of an element failed.
 * 	* ERR_ENCODING if interpretation of the serialized data failed.
 * @see lq_certificate_free
 */
int lq_certificate_deserialize(LQCert **cert, char *in, size_t in_len);


/***
 * @brief UNIMPLEMENTED verify the integrity of a certificate. Specifically that signatures in the certificate match given keys and data.
 * @param[in] Certificate to verify
 * @return ERR_OK if verified, or:
 * ....
 */
int lq_certificate_verify(LQCert *cert);


/***
 * @brief Free an instantiated certificate.
 * @param[in] Certificate to free.
 */
void lq_certificate_free(LQCert *cert);

#endif // LIBQAEDA_CERT_H_
