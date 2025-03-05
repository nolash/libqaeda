#ifndef LIBQAEDA_CRYPTO_H_
#define LIBQAEDA_CRYPTO_H_

#include <stddef.h>

#ifndef LQ_DIGEST_LEN
#define LQ_DIGEST_LEN 32
#endif

#ifndef LQ_PUBKEY_LEN
#define LQ_PUBKEY_LEN 65
#endif

#ifndef LQ_PRIVKEY_LEN
#define LQ_PRIVKEY_LEN 32
#endif

#ifndef LQ_SALT_LEN
#define LQ_SALT_LEN 32
#endif

enum lq_keystate_e {
	LQ_KEY_LOCK,
};


/**
 * \struct LQPrivKey 
 * 
 * \brief Represents an unencrypted private key for message signing.
 *
 * \see lq_privatekey_t
 */
struct lq_privatekey_t {
	short key_typ; ///< Key type identifier. Unused for now.
	char key_state; ///< Key state flags.
	void *impl; ///< Private key implementation object
};
typedef struct lq_privatekey_t LQPrivKey;

/**
 * \struct LQPubKey
 *
 * \brief Represents a public key embedded in private keys, certificates and signatures data.
 * 
 * \see lq_publickey_t 
 * \todo add serialization
 */
struct lq_publickey_t {
	short key_typ; ///< Key type identifier. Unused for now.
	LQPrivKey *pk; ///< Corresponding private key. Optional, and set to NULL if not available.
	void *impl; ///< Public key implementation object
};
typedef struct lq_publickey_t LQPubKey;

/**
 * \struct LQSig
 * 
 * \brief Represents a cryptographic signature over a message digest.
 *
 * \see lq_signature_t
 * \todo add serialization
 */
struct lq_signature_t {
	LQPubKey *pubkey; ///< Public key corresponding to the signature, used for verification. Optional (if public key can be recovered from signature)
	void *impl; ///< Signature implementation object
};
typedef struct lq_signature_t LQSig;

/**
 * @brief Create a new private key
 *
 * @param[in] Key material. If NULL, a new random private key will be generated.
 * @param[in] Length of key material. Ignored if seed parameter is NULL.
 * @return Pointer to new private key. Freeing the object is the caller's responsibility.
 * @see lq_privatekey_free
 */
LQPrivKey* lq_privatekey_new(const char *seed, size_t seed_len);

/**
 * @brief Get raw private key bytes
 * 
 * @param[in] Private key object.
 * @param[out] Pointer to start of data.
 * @return Length of key. If 0, no key could be found.
 */
size_t lq_privatekey_bytes(LQPrivKey *pk, char **out);

/**
 * @brief Create a new public key object. 
 *
 * @param[in] Uncompressed public key data.
 * @param[out] Pointer to new public key. Freeing the object is the caller's responsibility.
 * @see lq_publickey_free
 */
LQPubKey* lq_publickey_new(const char *full);

/**
 * @brief Create a new public key object from a private key. 
 *
 * @param[in] Private key to generate public key from.
 * @return Pointer to new public key. Freeing the object is the caller's responsibility.
 * @see lq_publickey_free
 */
LQPubKey* lq_publickey_from_privatekey(LQPrivKey *pk);

/**
 * @brief Get raw public key bytes
 * 
 * @param[in] Public key object.
 * @param[out] Pointer to start of data.
 * @return Length of key. If 0, no key could be found.
 */
size_t lq_publickey_bytes(LQPubKey *pubk, char **out);

/**
 * @brief Sign digest data using a private key.
 *
 * @param[in] Unencrypted private key to use for the signature.
 * @param[in] Message digest to sign.
 * @param[in] Length of message to sign.
 * @param[in] Salt data to use for the signature. Set to NULL if salt is not to be used. If not null, must be LQ_SALT_LEN long.
 * @return Signature object if signing was successful. Returns NULL if signature failed. It is the caller's responsiblity to free the signature.
 * @see lq_signature_free
 */
LQSig* lq_privatekey_sign(LQPrivKey *pk, const char *msg, size_t msg_len, const char *salt);

/**
 * @brief Create a signature object from byte data.
 *
 * @param[in] Signature byte data.
 * @param[in] Length of data.
 * @param[in] Public key used in signature. Can be NULL for recoverable signatures.
 * @return Signature object if parse was successful. Returns NULL if parsing failed. It is the caller's responsiblity to free the signature.
 */
LQSig* lq_signature_from_bytes(const char *sig_data, size_t sig_len, LQPubKey *pubkey);

/**
 * @brief Get raw signature bytes
 * 
 * @param[in] Signature object.
 * @param[out] Pointer to start of data.
 * @return Length of signature. If 0, no signature data could be found.
 */
size_t lq_signature_bytes(LQSig *sig, char **out);

/**
 * @brief Free an allocated public key.
 * @param[in] Public key to free.
 */
void lq_publickey_free(LQPubKey *pubk);

/**
 * @brief Free an allocated private key.
 * @param[in] Private key to free.
 */
void lq_privatekey_free(LQPrivKey *pk);


/**
 * @brief Free an allocated signature object.
 * @param[in] Private key to free.
 */
void lq_signature_free(LQSig *sig);


/**
 * @brief Calculate digest over arbitrary data.
 * @param[in] Data to calculate digest over.
 * @param[in] Length of data.
 * @param[out] Output buffer. Must be allocated to at least LQ_DIGEST_LENGTH
 * @return ERR_OK on success.
 */
int lq_digest(const char *in, size_t in_len, char *out);

#endif // LIBQAEDA_CRYPTO_H_
