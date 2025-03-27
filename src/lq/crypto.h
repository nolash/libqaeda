#ifndef LIBQAEDA_CRYPTO_H_
#define LIBQAEDA_CRYPTO_H_

#include <stddef.h>

#ifndef LQ_DIGEST_LEN
#define LQ_DIGEST_LEN 64
#endif

#ifndef LQ_PUBKEY_LEN
#define LQ_PUBKEY_LEN 64
#endif

#ifndef LQ_PRIVKEY_LEN
#define LQ_PRIVKEY_LEN 32
#endif

#ifndef LQ_SIGN_LEN
#define LQ_SIGN_LEN 64
#endif

#ifndef LQ_FP_LEN
#define LQ_FP_LEN 20
#endif

#ifndef LQ_SALT_LEN
#define LQ_SALT_LEN 32
#endif

#ifndef LQ_CRYPTO_BUFLEN
#define LQ_CRYPTO_BUFLEN 524288
#endif

#ifndef LQ_POINT_LEN
#define LQ_POINT_LEN 32
#endif

#define RERR_PFX_CRYPTO 0x100
/// Crypto backend unavailable
#define ERR_NOCRYPTO 0x101
/// Crypto authentication fail
#define ERR_KEYFAIL 0x102
/// Fail access to keyfile
#define ERR_KEYFILE 0x103
/// Last attempt to unlock key failed
#define ERR_KEY_UNLOCK 0x104
/// Usage of key for signature has been rejected (by user)
#define ERR_KEY_REJECT 0x105
/// Crypto resource fail
#define ERR_NOKEY 0x106

enum lq_keystate_e {
	LQ_KEY_INIT = 1,
	LQ_KEY_LOCK = 2,
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
 * \brief Perform necessary initializations of crypto component.
 *
 * \return ERR_OK on success.
 */
int lq_crypto_init();

/**
 * \brief Perform necessary resource release of crypto component.
 */
void lq_crypto_free();

/**
 * \brief Create a new private key
 *
 * If passphrase is not null the passphrase will be encrypted using that passphrase by default.
 *
 * \param[in] Key material. If NULL, a new random private key will be generated.
 * \param[in] Length of key material. Ignored if seed parameter is NULL.
 * \param[in] Passphrase to encrypt key with. If NULL, key will be encrypted with a single 0-byte as passphrase.
 * \param[in] Passphrase length. Ignored if passphrase is NULL.
 * \return Pointer to new private key. Freeing the object is the caller's responsibility.
 * \see lq_privatekey_free
 */
LQPrivKey* lq_privatekey_new(const char *seed, size_t seed_len, const char *passphrase, size_t passphrase_len);

/**
 * \brief Get raw private key bytes
 * 
 * \param[in] Private key object.
 * \param[out] Pointer to start of data.
 * \return Length of key. If 0, no key could be found.
 */
size_t lq_privatekey_bytes(LQPrivKey *pk, char **out);

/**
 * \brief Create a new public key object. 
 *
 * \param[in] Uncompressed public key data.
 * \param[out] Pointer to new public key. Freeing the object is the caller's responsibility.
 * \see lq_publickey_free
 */
LQPubKey* lq_publickey_new(const char *full);

/**
 * \brief Create a new public key object from a private key. 
 *
 * \param[in] Private key to generate public key from.
 * \return Pointer to new public key. Freeing the object is the caller's responsibility.
 * \see lq_publickey_free
 */
LQPubKey* lq_publickey_from_privatekey(LQPrivKey *pk);

/**
 * \brief Get raw public key bytes
 * 
 * \param[in] Public key object.
 * \param[out] Pointer to start of data.
 * \return Length of key. If 0, no key could be found.
 */
size_t lq_publickey_bytes(LQPubKey *pubk, char **out);

/**
 * \brief Encrypt private key in place.
 * 
 * Must clear sensistive memory.
 *
 * \param[in] Private Key object
 * \return ERR_OK if encrypted, ERR_NOOP if already encrypted, or ERR_INIT if encryption fails.
 */
int lq_privatekey_lock(LQPrivKey *pk, const char *passphrase, size_t passphrase_len);

/**
 * \brief Decrypt private key in place.
 * 
 * \param[in] Private Key object
 * \return ERR_OK if decrypted, ERR_NOOP if not encrypted, or ERR_INIT if decryption fails.
 */
int lq_privatekey_unlock(LQPrivKey *pk, const char *passphrase, size_t passphrase_len);

/**
 * \brief Sign digest data using a private key.
 *
 * \param[in] Unencrypted private key to use for the signature.
 * \param[in] Message digest to sign.
 * \param[in] Length of message to sign.
 * \param[in] Salt data to use for the signature. Set to NULL if salt is not to be used. If not null, must be LQ_SALT_LEN long.
 * \return Signature object if signing was successful. Returns NULL if signature failed. It is the caller's responsiblity to free the signature.
 * \see lq_signature_free
 */
LQSig* lq_privatekey_sign(LQPrivKey *pk, const char *msg, size_t msg_len, const char *salt);

/**
 * \brief Create a signature object from byte data.
 *
 * \param[in] Signature byte data.
 * \param[in] Length of data.
 * \param[in] Public key used in signature. Can be NULL for recoverable signatures.
 * \return Signature object if parse was successful. Returns NULL if parsing failed. It is the caller's responsiblity to free the signature.
 */
LQSig* lq_signature_from_bytes(const char *sig_data, size_t sig_len, LQPubKey *pubkey);

/**
 * \brief Get raw signature bytes
 * 
 * \param[in] Signature object.
 * \param[out] Pointer to start of data.
 * \return Length of signature. If 0, no signature data could be found.
 */
size_t lq_signature_bytes(LQSig *sig, char **out);

/**
 * \brief Verify a signature against a private key and message.
 *
 */
int lq_signature_verify(LQSig *sig, const char *msg, size_t msg_len);

/**
 * \brief Free an allocated public key.
 * \param[in] Public key to free.
 */
void lq_publickey_free(LQPubKey *pubk);

/**
 * \brief Free an allocated private key.
 * \param[in] Private key to free.
 */
void lq_privatekey_free(LQPrivKey *pk);


/**
 * \brief Free an allocated signature object.
 * \param[in] Private key to free.
 */
void lq_signature_free(LQSig *sig);


/**
 * \brief Calculate digest over arbitrary data.
 * \param[in] Data to calculate digest over.
 * \param[in] Length of data.
 * \param[out] Output buffer. Must be allocated to at least LQ_DIGEST_LENGTH
 * \return ERR_OK on success.
 */
int lq_digest(const char *in, size_t in_len, char *out);

#endif // LIBQAEDA_CRYPTO_H_
