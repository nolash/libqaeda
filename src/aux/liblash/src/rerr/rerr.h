#ifndef RERR_H_
#define RERR_H_

enum err_base_e {
	ERR_OK,
	ERR_FAIL,
	ERR_SUPPORT,
	ERR_INIT,
	ERR_NOOP,
	ERR_NOENT,
	ERR_READ,
	ERR_WRITE,
	ERR_MEM,
	ERR_COMPAT,
	ERR_ENCODING,
	ERR_BYTEORDER,
	ERR_OVERFLOW,
	ERR_UNDERFLOW,
	ERR_EOF,
};

#ifndef RERR_N_PFX 
#define RERR_N_PFX 0
#endif

#ifndef RERR_NOTFOUND_RESPONSE
#define RERR_NOTFOUND_RESPONSE "(unregistered)"
#endif

void rerr_init(const char *coreprefix);
void rerr_register(int pfx, char *label, void *start);
char* rerrstr(int code, char *buf);
char* rerrstrv(int code);
const char* rerrpfx(int code);

#endif // RERR_H
