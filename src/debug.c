#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>

#include <llog.h>
#include <rerr.h>

#include "lq/mem.h"
#include "debug.h"

static int default_fd = 2;
static char nl = 0x0a;


int debug_fd(int fd) {
	if (fcntl(fd, F_GETFD) < 0) {
		return 1;
	};
	default_fd = fd;
	return 0;
}


static void debug_write(int fd, const char *s) {
	size_t r;
	size_t l;
	size_t c;
	char *p;
	
	l = strlen(s);
	c = 0;
	p = (char*)s;
	while (c < l) {
		r = write(fd, p, l - c);
		p += r;
		c += r;
	}
	write(fd, &nl, 1);
}

void llog_out(const char *s) {
	debug_write(default_fd, s);
}

static void debug_out(enum lloglvl_e lvl, const char *ns, const char *msg) {
	char *p;

	p = llog_new_ns(lvl, (char*)msg, (char*)ns);
	llog_out(p);
}

void debug(enum lloglvl_e lvl, const char *ns, const char *msg) {
	debug_out(lvl, (char*)ns, (char*)msg);
}

void debug_x(enum lloglvl_e lvl, const char *ns, const char *msg, int argc, ...) {
	int i;
	long long l;
	char *k;
	char *p;
	enum debug_typ_e typ;
	void *v;	
	va_list vv;

	va_start(vv, argc);

	p = llog_new_ns(lvl, (char*)msg, (char*)ns);

	for (i = 0; i < argc; i++) {
		typ = va_arg(vv, enum debug_typ_e);
		l = va_arg(vv, int);
		k = va_arg(vv, char*);
		switch (typ) {
			case MORGEL_TYP_BIN:
				v = va_arg(vv, char*);
				llog_add_b(k, v, l);
				break;
			case MORGEL_TYP_STR:
				v = va_arg(vv, char*);
				llog_add_s(k, v);
				break;
			case MORGEL_TYP_NUM:
				l = va_arg(vv, long long);
				llog_add_n(k, l);
				break;
		}
	}
	llog_out(p);
	va_end(vv);
}

int debug_logerr(enum lloglvl_e lvl, int err, char *msg) {
	char *e;
	char *s;

	if (msg == 0) {
		msg = "(debug logerr)";
	}
	s = (char*)rerrpfx(err);
	e = llog_new_ns(lvl, msg, s);
	e = llog_add_x("errcode", err);
	s = rerrstrv(err);
	e = llog_add_s("err", s);
	llog_out(e);
	return err;
}
