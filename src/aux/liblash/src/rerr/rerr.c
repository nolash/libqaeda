#include "rerr.h"

#ifdef RERR
static char** rerr[RERR_N_PFX + 1];
static const char* rerr_pfx[RERR_N_PFX + 1];
char *rerr_base[3] = {
	"OK",
	"FAIL",
	"UNSUPPORTED",
};
#endif

void rerr_init(const char *coreprefix) {
#ifdef RERR
	int i;

	for (i = 1; i < RERR_N_PFX + 1; i++) {
		rerr[i] = 0x0;
		rerr_pfx[i] = 0x0;	
	}
	rerr[0] = rerr_base;
	rerr_pfx[0] = coreprefix;
#endif
}

void rerr_register(int pfx, char *label, void *start) {
#ifdef RERR
	pfx >>= 8;
	rerr_pfx[pfx] = label;
	rerr[pfx] = start;
#endif
}

#ifdef RERR
static void splitcode(int code, short *k, char *v) {
	*v = code & 0xff;
	*k = 0;
	if (code > 0xff) {
		*k = ((code >> 8) & 0xffff);
	}
}

static char *strv(short k, char v) {
	return (char*)(*(rerr[k]+v));
}
#endif

const char *rerrpfx(int code) {
#ifdef RERR
	short k;
	char v;
	splitcode(code, &k, &v);
	return rerr_pfx[k];
#else
	return "";
#endif
}

char *rerrstrv(int code) {
#ifdef RERR
	short k;
	char v;
	splitcode(code, &k, &v);
	return strv(k, v);
#else
	return "";
#endif
}

char* rerrstr(int code, char *buf) {
#ifdef RERR
	short k;
	char v;
	char *src;
	char *dst;

	splitcode(code, &k, &v);

	dst = buf;
	src = (char*)rerr_pfx[k];
	if (src) {
		while (1) {
			if (*src == 0) {
				break;
			}
			*dst = *src;
			src++;
			dst++;
		}
		*dst = ':';
		dst++;
		*dst = ' ';
		dst++;
	}

	src = strv(k, v);
	//src = (char*)(*(rerr[k]+v));
	while (1) {
		if (*src == 0) {
			break;
		}
		*dst = *src;
		src++;
		dst++;
	}

	*dst = 0;

	return buf;
#else
	return 0;
#endif
}

