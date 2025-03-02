#ifndef LIBQAEDA_ERR_H_
#define LIBQAEDA_ERR_H_

enum err_e {
	ERR_OK,
	ERR_BYTEORDER,
	ERR_OVERFLOW,
	ERR_INIT,
	ERR_READ,
	ERR_WRITE,
	ERR_ENCODING,
};

typedef enum err_e LQErr;

#endif // LIBQAEDA_ERR_H_

