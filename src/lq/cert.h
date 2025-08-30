///file @cert.h
#ifndef LIBQAEDA_CERT_H_
#define LIBQAEDA_CERT_H_

#include <stddef.h>

#include "lq/crypto.h"
#include "lq/msg.h"
#include "lq/store.h"

#ifndef LQ_CERT_DOMAIN_LEN
#define LQ_CERT_DOMAIN_LEN 8
#endif

enum lq_certificate_state_e {
	CERT_NONE = 0,
	CERT_REQUEST = 1,
	CERT_RESPONSE = 2,
	CERT_CHAIN = 4,
};

/**
 * \struct LQCert
 *
 * \brief A certificate is a counter-signed piece of arbitrary data within a designated domain. It may or may not be linked to a previous certificate.
 *
 * \see lq_certificate_t
 */
typedef struct lq_certificate_t LQCert;
struct lq_certificate_t {
	char domain[LQ_CERT_DOMAIN_LEN]; ///< Domain data is used by application data to evaluate whether a record is relevant for it or not.
	LQMsg *request; ///< A request message encapsulates an arbitrary string of data that should be confirmed by a responder.
	LQSig *request_sig; ///< Signature over a request message and the linked certificate. If the linked certificate is NULL, the certificate data used in the signature with be a LQ_DIGEST_LEN string with all bytes set to 0.
	LQMsg *response; ///< A response message encapsulates an arbitrary string of data that confirms a request. This field must be NULL unless a signed requests exists.
	LQSig *response_sig; ///< Signature over a response message. This field must be NULL unless a response message is set. The signature is calculated over both the response and the signed request.
	LQCert *parent; ///< Link to previous certificate. Optional. Set to NULL if no link exists.
	char parent_hash[LQ_DIGEST_LEN];
	LQResolve *resolve; ///< Optional store implementation to resolve message hashes to content.
};

/**
 * \brief Create a new certificate.
 *
 * \param[in] Previous certificate to link to.
 * \return The allocated certificate object. It is the caller's responsibility to free the object.
 *
 * \see lq_certificate_free
 */
LQCert* lq_certificate_new(LQCert *parent);

/**
 * \brief Set the domain of the certificate.
 *
 * If not set, the default domain value will be used, which is LQ_DOMAIN_LEN bytes set to 0.
 *
 * \param[in] Instantiated certificate to set domain on.
 * \param[in] Domain data. Must be LQ_DOMAIN_LEN bytes long.
 */
void lq_certificate_set_domain(LQCert *cert, const char *domain);

/**
 * \brief Receive the message signature material for the current state of the certificate.
 */
char* lq_certificate_mat(const LQCert *cert, const LQPubKey *pubk, char *out);

/**
 * \brief Sign the next pending message in the certificate.
 *
 * If the request message is set but not signed, the request message will be signed. If the response message is set but not signed, the response message will be signed. The limitations described in the struct declaration apply.
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
 * \param[in] Instantiated certificate to perform signature on.
 * \param[in] Store implementations to use for resolving content key from deserialized message and certificate data. If NULL, content will not be resolved.
 * \param[in] Private key to use for signature.
 * \return ERR_OK on successful signature, or:
 * 	* ERR_REQUEST if request has already been signed  (and response is not set)
 * 	* ERR_RESPONSE if response has already been signed.
 * 	* ERR_ENCODING if calculateing the signature failed.
 * 	* ERR_INIT if no message eligible for signature exists.
 *
 * \see lq_certificate_request
 * \see lq_certificate_respond
 */
int lq_certificate_sign(LQCert *cert, LQPrivKey *pk);

/**
 * \brief Serialize certificate data payload for storage and transport.
 *
 * \param[in] Certificate to serialize
 * \param[out] Buffer to write data to.
 * \param[out] Value behind pointer must contain the capacity of the output buffer. Will be overwritten with the actual number of bytes written.
 * \return ERR_OK if serialization is successful, or:
 * 	* ERR_INIT if the serialization object couldn't be instantiated.
 * 	* ERR_OVERFLOW if output exceeded the available space in output buffer.
 * 	* ERR_WRITE if serialization of an element failed.
 * 	* ERR_ENCODING if generating the final serialization string failed.
 */
int lq_certificate_serialize(LQCert *cert, char *out, size_t *out_len);

/**
 * \brief Deserialize certificate data payload from storage or transport.
 *
 * \param[out] Pointer to where certificate will be instantiated. It is the caller's responsibility to free the certificate object.
 * \param[in] Store implementations to use for resolving content key from deserialized message and certificate data. If NULL, content will not be resolved.
 * \param[in] Serialized data.
 * \param[in] Length of serialized data.
 * \return ERR_OK if deserialization is successful, or:
 * 	* ERR_INIT if the serialization object couldn't be instantiated.
 * 	* ERR_READ if deserialization of an element failed.
 * 	* ERR_ENCODING if interpretation of the serialized data failed.
 * \see lq_certificate_free
 */
int lq_certificate_deserialize(LQCert **cert, LQResolve *resolve, char *in, size_t in_len);


/**
 * \brief Verify the integrity of a certificate. Specifically that signatures in the certificate match given keys and data.
 *
 * The cert must have either
 * - no message (NOOP)
 * - request message and request_message signature
 * - request AND response message, with request AND response signatures
 *
 * Messages must have public key set.
 *
 * The public key pointers in the output parameters are valid until the certificate is freed.
 *
 * \param[in] Certificate to verify
 * \param[in] Store implementations to use for resolving content key from deserialized message and certificate data. If NULL, content will not be resolved.
 * \param[out] If not NULL, provides location to store pointer to request publickey. If certificate does not contain a valid request, this will be set to NULL.
 * \param[out] If not NULL, provider location to store pointer to response publickey. If certificate does not contain a valid response, this will be set to NULL.
 * \return ERR_OK if verified, ERR_NOOP if no message.
 */
int lq_certificate_verify(LQCert *cert, LQPubKey **request_pubkey, LQPubKey **response_pubkey);


/***
 * \brief Add and optionally sign a request message to the certificate.
 *
 * The signature will be calculated over the certificate data.
 *
 * Fails if a request or response message and/or signature already exists.
 *
 * Message is freed as part of lq_certificate_free.
 *
 * \param[in] Certificate to manipulate.
 * \param[in] Request message
 * \param[in] If not NULL, sign request with the given private key.
 * \return ERR_OK on success.
 */
int lq_certificate_request(LQCert *cert, LQMsg *req, LQPrivKey *pk);

/***
 * \brief Add and optionally sign a response message to the certificate.
 *
 * The signature will be calculated over the certificate data and the existing request.
 *
 * Fails if a request and/or signature does not exist.
 *
 * Fails if a response and/or signature already exists.
 *
 * Message is freed as part of lq_certificate_free.
 *
 * \param[in] Certificate to manipulate.
 * \param[in] Response message
 * \param[in] If not NULL, sign response with the given private key.
 * \return ERR_OK on success.
 */
int lq_certificate_respond(LQCert *cert, LQMsg *rsp, LQPrivKey *pk);


/**
 * Set parent hash explicitly on certificate.
 *
 * Fails if certicicate already holds a parent certificate object (was created with a non-null parent cert value).
 *
 * \param[in] Certificate to manipulate.
 * \param[in] Digest data. Must be LQ_DIGEST_LEN long.
 * \return ERR_DUP if parent object exists, or ERR_OK on success.
 */
int lq_certificate_set_parent_digest(LQCert *cert, const char *b);

/**
 * Set the content resolver to use for serializations.
 *
 * \param[in] Certificate to manipulate.
 * \param[in] Store implementations to use for storing serialized certificate and message data. If NULL, content will not be looked up from resolver.
 */
void lq_certificate_set_resolver(LQCert *cert, LQResolve *resolve);

/**
 * Create a digest of the certificate, to use as the parent hash.
 *
 * Fails if certicicate does not have a response signature.
 *
 * \param[in] Certificate to manipulate.
 * \param[in] Store implementations to use for storing serialized certificate and message data. If NULL, content will not be looked up from resolver.
 * \param[out] Digest output.
 * \return ERR_NONSENSE if response missing, ERR_FAIL if serialize fails, ERR_DIGEST if digest fails, or ERR_OK on success.
 */
int lq_certificate_digest(LQCert *cert, char *out);

/**
 * \brief Free an instantiated certificate.
 *
 * Also frees any messages and signatures assigned in the certificate.
 *
 * \param[in] Certificate to free.
 */
void lq_certificate_free(LQCert *cert);


#endif // LIBQAEDA_CERT_H_
