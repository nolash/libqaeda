#ifndef LIBQAEDA_ERR_H_
#define LIBQAEDA_ERR_H_

// provides ERR_OK = 0, ERR_FAIL = 1, ERR_UNIMPLEMENTED = 2
#include <rerr.h> 

/// Error values used across all error contexts.
enum err_e {
	ERR_NOOP = 3, ///< No action taken.
	ERR_BYTEORDER, ///< Errors related to endianness
	ERR_OVERFLOW, ///< Not enough space to write
	ERR_INIT, ///< Failure instantiating object or data
	ERR_MEM, ///< Failure allocating memory
	ERR_READ, ///< General data read failure
	ERR_WRITE, ///< General data write failure
	ERR_ENCODING, ///< Failure in serialization and data transformation
	ERR_REQUEST, ///< Error related to certificate request messages
	ERR_RESPONSE, ///< Error related to certificate response messages
	ERR_NOENT, ///< Object not found
	ERR_COMPAT, ///< Incompatible data or format
	ERR_CRYPTO, ///< Crypto related error
};

typedef enum err_e LQErr;

#endif // LIBQAEDA_ERR_H_

