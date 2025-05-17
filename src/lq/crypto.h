#ifndef LIBQAEDA_CRYPTO_H_
#define LIBQAEDA_CRYPTO_H_

#include <stddef.h>

#include "base.h"
#include "store.h"

#ifndef LQ_DIGEST_LEN
/**
 * \brief Length of result produced by digest algorithm.
 */
#define LQ_DIGEST_LEN 64
#endif

#ifndef LQ_DIGEST_SIG_LEN
/**
 * \brief Length of digest expected by signature.
 */
#define LQ_DIGEST_SIG_LEN LQ_DIGEST_LEN
#endif

#ifndef LQ_PUBKEY_LEN
/**
 * \brief Length in bytes of the full publickey representation.
 */
#define LQ_PUBKEY_LEN 32
#endif

#ifndef LQ_PRIVKEY_LEN
/**
 * \brief Length of the literal private key bytes.
 */
#define LQ_PRIVKEY_LEN 32
#endif

#ifndef LQ_SIGN_LEN
/**
 * \brief Length of the full signature output.
 */
#define LQ_SIGN_LEN 64
#endif

#ifndef LQ_FP_LEN
/**
 * \brief Length of the public key fingerprint data.
 */
#define LQ_FP_LEN 20
#endif

#ifndef LQ_SALT_LEN
/**
 * \brief Length of salt used in signatures.
 */
#define LQ_SALT_LEN 32
#endif

#ifndef LQ_CRYPTO_BUFLEN
/**
 * \brief Length of internal work buffer for crypto and signature operations.
 */
#define LQ_CRYPTO_BUFLEN 65536
#endif

#ifndef LQ_CRYPTO_BLOCKSIZE
/**
 * \brief Storage size unit for encrypted data. Encrypted, padded data will be stored in a multiplier of this size.
 */
#define LQ_CRYPTO_BLOCKSIZE LQ_BLOCKSIZE
#endif

#ifndef LQ_POINT_LEN
/**
 * \brief Size of coordinate point on cryptographic curve.
 */
#define LQ_POINT_LEN 32
#endif


/**
 * \brief State of private key.
 */
enum lq_keystate_e {
	LQ_KEY_INIT = 1, ///< Key contains valid data.
	LQ_KEY_LOCK = 2, ///< Key is locked with passphrase.
};

/**
 * \struct LQPrivKey 
 * 
 * \brief Represents a private key used for message signing.
 *
 * \see lq_privatekey_t
 */
struct lq_privatekey_t {
	short key_typ; ///< Key type identifier. Unused for now.
	unsigned char key_state; ///< Key state flags.
	void *impl; ///< Private key implementation object
};
typedef struct lq_privatekey_t LQPrivKey;

/**
 * \struct LQPubKey
 *
 * \brief Represents a public key, to include with certificates and signatures.
 * 
 * \see lq_publickey_t 
 *
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
 * The public key must be set in order to use this signature in verification.
 *
 * \see lq_signature_t
 * \see lq_signature_verify
 *
 * \todo add serialization
 *
 */
struct lq_signature_t {
	LQPubKey *pubkey; ///< Public key corresponding to the signature, used for verification. Optional (if public key can be recovered from signature)
	void *impl; ///< Signature implementation object
};
typedef struct lq_signature_t LQSig;

/**
 * \brief Initialize crypto component internals.
 *
 * \return ERR_OK on success.
 */
int lq_crypto_init(const char *base);

/**
 * \brief Free resources used by crypto component internals.
 **/
void lq_crypto_free();

/**
 * \brief Create a new private key
 *
 * If passphrase is not null the passphrase will be encrypted using that passphrase by default.
 *
 * \param[in] Passphrase to encrypt key with. If NULL, key will be encrypted with a single 0-byte as passphrase.
 * \param[in] Passphrase length. Ignored if passphrase is NULL.
 * \return Pointer to new private key. Freeing the object is the caller's responsibility.
 *
 * \see lq_privatekey_free
 */
LQPrivKey* lq_privatekey_new(const char *passphrase, size_t passphrase_len);

/**
 * \brief Load a private key from store.
 *
 * If passphrase is not null the passphrase will be encrypted using that passphrase by default.
 *
 * \param[in] Passphrase to encrypt key with. If NULL, key will be encrypted with a single 0-byte as passphrase.
 * \param[in] Passphrase length. Ignored if passphrase is NULL.
 * \param[in] If not NULL, the private key matching the fingerprint will be loaded. If not, a "default" key will be loaded.
 * \return Pointer to new private key, if found, or NULL if not. Freeing the object is the caller's responsibility.
 *
 * \see lq_privatekey_free
 */
LQPrivKey* lq_privatekey_load(const char *passphrase, size_t passphrase_len, const char *fingerprint);

/**
 * \brief Get the raw private key bytes.
 * 
 * \param[in] Private key object.
 * \param[out] Pointer to start of data to write to. The buffer must be at least LQ_PRIVKEY_LEN long.
 * \return Length of key. If 0, no key could be found.
 */
size_t lq_privatekey_bytes(LQPrivKey *pk, char **out);

/**
 * \brief Create a new public key object. 
 *
 * \param[in] Uncompressed public key data.
 * \return Pointer to new public key. Freeing the object is the caller's responsibility.
 *
 * \see lq_publickey_free
 */
LQPubKey* lq_publickey_new(const char *full);

/**
 * \brief Create a new public key object from a private key. 
 *
 * Will set the private key property with the given private key. The private key must be freed independently.
 *
 * \param[in] Private key to generate public key from.
 * \return Pointer to new public key. Freeing the object is the caller's responsibility.
 *
 * \see lq_publickey_free
 */
LQPubKey* lq_publickey_from_privatekey(LQPrivKey *pk);

/**
 * \brief Get raw public key bytes.
 * 
 * \param[in] Public key object.
 * \param[out] Pointer to start of data.
 * \return Length of key. If 0, no key could be found.
 */
size_t lq_publickey_bytes(LQPubKey *pubk, char **out);

/**
 * \brief Get the public key fingerprint bytes.
 *
 * \param[in] Public key object
 * \param[out] Pointer to start of data to write to. Buffer must have a capacity of at least LQ_PUBKEY_LEN bytes.
 * \return Length of fingerprint data. If 0, no fingerprint could be found.
 */
size_t lq_publickey_fingerprint(LQPubKey *pubk, char **out);

/**
 * \brief Compare two public keys.
 *
 * \param[in] First public key to compare.
 * \param[in] Second public key to compare.
 * \return ERR_OK if the public key objects represent the same public key.
 */
int lq_publickey_match(LQPubKey *left, LQPubKey *right);

/**
 * \brief Encrypt private key in place.
 * 
 * Must clear sensistive memory.
 *
 * \param[in] Private Key object.
 * \param[in] Passphrase to encrypt private key with.
 * \param[in] Length of passphrase.
 * \return ERR_OK if encrypted, ERR_NOOP if already encrypted, or ERR_INIT if encryption fails.
 */
int lq_privatekey_lock(LQPrivKey *pk, const char *passphrase, size_t passphrase_len);

/**
 * \brief Decrypt private key in place.
 * 
 * \param[in] Private Key object.
 * \param[in] Passphrase to decrypt private key with.
 * \param[in] Length of passphrase.
 * \return ERR_OK if decrypted, ERR_NOOP if not encrypted, or ERR_INIT if decryption fails.
 */
int lq_privatekey_unlock(LQPrivKey *pk, const char *passphrase, size_t passphrase_len);

/**
 * \brief Sign digest data using a private key.
 *
 * \param[in] Decrypted private key to use for the signature.
 * \param[in] Message digest to sign.
 * \param[in] Length of message to sign. Must be 
 * \param[in] Salt data to use for the signature. Set to NULL if salt is not to be used. If not null, must be LQ_SALT_LEN long.
 * \return Signature object if signing was successful. Returns NULL if signature failed. It is the caller's responsiblity to free the signature.
 *
 * \todo Remove msg_len, as it is inferred by LQ_DIGEST_SIG_LEN
 *
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
 *
 * \todo Remove sig_len, as it is inferred by LQ_SIG_LEN
 */
LQSig* lq_signature_from_bytes(const char *sig_data, size_t sig_len, LQPubKey *pubkey);

/**
 * \brief Get raw signature bytes
 * 
 * \param[in] Signature object.
 * \param[out] Pointer to start of data to write to. Buffer must have a capacity of at least LQ_SIG_LEN bytes.
 * \return Length of signature. If 0, no signature data could be found.
 */
size_t lq_signature_bytes(LQSig *sig, char **out);

/**
 * \brief Verify a signature against a private key and message.
 *
 * \param[in] Message digest to sign.
 * \param[in] Length of message to sign.
 * \return ERR_OK if signature is verified.
 *
 * \todo remove msg_len, as it is inferred by LQ_DIGEST_SIG_LEN
 */
int lq_signature_verify(LQSig *sig, const char *msg, size_t msg_len);

/**
 * \brief Free an allocated public key.
 *
 * Does not free the associated private key.
 *
 * \param[in] Public key to free.
 */
void lq_publickey_free(LQPubKey *pubk);

/**
 * \brief Free an allocated private key.
 *
 * \param[in] Private key to free.
 */
void lq_privatekey_free(LQPrivKey *pk);

/**
 * \brief Free an allocated signature object.
 *
 * \param[in] Private key to free.
 */
void lq_signature_free(LQSig *sig);

/**
 * \brief Retrieve the store object used for the crypto component.
 *
 * Cannot be called before lq_crypto_init()
 *
 * \returns The LQStore object.
 * \see lq_crypto_init
 */
LQStore* lq_crypto_store();

/**
 * \brief Calculate digest over arbitrary data using the default algorithm.
 *
 * \param[in] Data to calculate digest over.
 * \param[in] Length of data.
 * \param[out] Output buffer. Buffer must have a capacity of at least LQ_DIGEST_LENGTH bytes.
 * \return ERR_OK on success.
 */
int lq_digest(const char *in, size_t in_len, char *out);

#endif // LIBQAEDA_CRYPTO_H_
