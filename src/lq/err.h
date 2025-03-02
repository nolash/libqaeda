#ifndef LIBQAEDA_ERR_H_
#define LIBQAEDA_ERR_H_

/// Error values used across all error contexts.
enum err_e {
	ERR_OK, ///< No error
	ERR_BYTEORDER, ///< Errors related to endianness
	ERR_OVERFLOW, ///< Not enough space to write
	ERR_INIT, ///< Failure instantiating object or data
	ERR_READ, ///< General data read failure
	ERR_WRITE, ///< General data write failure
	ERR_ENCODING, ///< Failure in serialization and data transformation
	ERR_REQUEST, ///< Error related to certificate request messages
	ERR_RESPONSE, ///< Error related to certificate response messages
	ERR_NOENT, ///< Not found
	ERR_COMPAT, ///< Incompatible data or format
};

typedef enum err_e LQErr;

#endif // LIBQAEDA_ERR_H_

