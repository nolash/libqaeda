#ifndef LIBQAEDA_ERR_H_
#define LIBQAEDA_ERR_H_

#define LQ_ERRSIZE 1024

// provides ERR_OK = 0, ERR_FAIL = 1, ERR_UNIMPLEMENTED = 2
#include <rerr.h> 

/// Error values used across all error contexts.
enum err_e {
	RERR_PFX_LQ = 0x100,
	ERR_NONSENSE = 0x101, ///< Available data does not make sense in context
	ERR_REQUEST = 0x102, ///< Error related to certificate request messages
	ERR_RESPONSE = 0x103, ///< Error related to certificate response messages
	ERR_RESOLVE = 0x104, ///< Error related to resolving message hashes

	RERR_PFX_CRYPTO = 0x200,
	ERR_NOCRYPTO = 0x201,
	ERR_KEYFAIL = 0x202,
	ERR_KEYFILE = 0x203,
	ERR_KEY_UNLOCK = 0x204,
	ERR_KEY_LOCK = 0x205,
	ERR_KEY_REJECT = 0x206,
	ERR_NOKEY = 0x207,
	ERR_CIPHER = 0x208,
	ERR_DIGEST = 0x209,
	ERR_SIGFAIL = 0x20a,
	ERR_SIGVALID = 0x20b,

	RERR_PFX_STORE = 0x300,
	ERR_STORE_AVAIL = 0x301,

	RERR_PFX_CERT = 0x400,
	ERR_DUP = 0x401,
	ERR_SEQ = 0x402,
};

void lq_err_init();

#endif // LIBQAEDA_ERR_H_
