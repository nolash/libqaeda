#ifndef RERR_H_
#define RERR_H_

#define ERR_OK 0x0
#define ERR_FAIL 0x1
#define ERR_UNSUPPORTED 0x2

#ifndef RERR_N_PFX 
#define RERR_N_PFX 0
#endif

void rerr_init(const char *coreprefix);
void rerr_register(int pfx, char *label, void *start);
char* rerrstr(int code, char *buf);
char* rerrstrv(int code);
const char* rerrpfx(int code);

#endif // RERR_H
