#ifndef LIBQAEDA_STORE_H_
#define  LIBQAEDA_STORE_H_

#include <stddef.h>

/// Payload type hint to control how and what a store implementation executes persistence.
enum payload_e {
	LQ_CONTENT_RAW,
	LQ_CONTENT_MSG,
	LQ_CONTENT_CERT,	
	LQ_CONTENT_KEY,
};

/***
 * @struct LQStore
 * @brief Store interface, implemented by all IO backends; network, db, filesystem and memory.
 * @var LQStore::store_typ
 * Store type identifier, used for implementation methods to ensure that the correct version of a store structure has been passed.
 * @var LQStore::userdata
 * Implementation specific data required by the specific store.
 * @var LQStore::get
 * Interface for retrieving data corresponding to a key.
 * @var LQStore::put
 * Interface for storing data corresponding to a key.
 */
typedef struct lq_store_t LQStore;
struct lq_store_t {
	int store_typ;
	void *userdata;
	int (*get)(enum payload_e typ, LQStore *store, const char *key, size_t key_len, char *value, size_t *value_len);
	int (*put)(enum payload_e typ, LQStore *store, const char *key, size_t *key_len, char *value, size_t value_len);
	void (*free)(LQStore *store);
};


/***
 * @struct LQResolve
 * @brief A linked list of stores that should be used for a specific context or action.
 * @var LQResolve::store
 * Store interface implementation.
 * @var LQResolve::next
 * Provides access to next store implementation to store to or retrieve from. Setting to NULL stops any further action.
 * @todo Add a list of content types, for while store action will be taken and otherwise ignored.
 */
typedef struct lq_resolve_t LQResolve;
struct lq_resolve_t {
	LQStore *store;
	LQResolve *next;	
};

#endif // LIBQAEDA_STORE_H_
