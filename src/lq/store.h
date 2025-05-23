#ifndef LIBQAEDA_STORE_H_
#define  LIBQAEDA_STORE_H_

#include <stddef.h>

#ifndef LQ_STORE_KEY_MAX
#define LQ_STORE_KEY_MAX 256
#endif

#ifndef LQ_STORE_VAL_MAX
#define LQ_STORE_VAL_MAX 65536
#endif

/// Payload type hint to control how and what a store implementation executes persistence.
/// Not currently in active use.
enum payload_e {
	LQ_CONTENT_RAW, ///< Arbitrary data.
	LQ_CONTENT_MSG, ///< Data is a message type.
	LQ_CONTENT_CERT, ///< Data is a cert type.
	LQ_CONTENT_KEY, ///< Data is a private key type.
	LQ_CONTENT_KEY_PUBLIC, ///< Data is a public key type.
};

/**
 * \struct LQStore
 *
 * \brief Store interface, implemented by all IO backends; network, db, filesystem and memory.
 * 
 * \see lq_store_t
 */
typedef struct lq_store_t LQStore;
struct lq_store_t {
	int store_typ; ///< Store type identifier, used for implementation methods to ensure that the correct version of a store structure has been passed.
	void *userdata; ///< Implementation specific data required by the specific store.
	int (*get)(enum payload_e typ, LQStore *store, const char *key, size_t key_len, char *value, size_t *value_len); ///< Interface for retrieving data corresponding to a key.
	int (*put)(enum payload_e typ, LQStore *store, const char *key, size_t *key_len, char *value, size_t value_len); ///< Interface for storing data corresponding to a key.
	int (*count)(enum payload_e typ, LQStore *store, const char *key, size_t key_len); ///< Interface for returning number of entries under a key.
	void (*free)(LQStore *store); ///< Interface for cleaning up implementation specific resources in use by the store.
};


/**
 * \struct LQResolve
 *
 * \brief A linked list of stores that should be used for a specific context or action.
 * 
 * \see lq_resolve_t 
 * 
 * \todo Add a list of content types, for while store action will be taken and otherwise ignored.
 */
typedef struct lq_resolve_t LQResolve;
struct lq_resolve_t {
	LQStore *store; ///< Store interface implementation.
	LQResolve *next; ///< Provides access to next store implementation to store to or retrieve from. Setting to NULL stops any further action.
};

/**
 * \brief Instantiate a new store from the given path or connection spec.
 * 
 * Caller must free the store after use with lq_store_free.
 *
 * \param[in] Connection string or path.
 * \return A new store object, or NULL by failure.
 *
 * \see lq_store_free
 */
LQStore* lq_store_new(const char *spec);

/**
 * \brief Release resources used by the store.
 * 
 * \param[in] The store to operate on.
 */
void lq_store_free(LQStore *store);

#endif // LIBQAEDA_STORE_H_
