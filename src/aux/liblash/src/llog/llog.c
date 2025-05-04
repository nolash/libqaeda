#include "llog.h"
#include "hex.h"


char lloglvl_str[][4]  = {
	"???",
	"crt",
	"err",
	"wrn",
	"inf",
	"dbg",
	"gru",
	"usr",
};

char _llogbuf_v[LLOG_LENGTH];
char* _llogbuf = (char*)_llogbuf_v;
int _llogbuf_crsr;

static int cpy(const char *s) {
	char *p;
	int c;

	p = _llogbuf + _llogbuf_crsr;
	c = 0;
	while (1) {
		if (*s == 0) {
			break;
		}
		*p = *s;
		s++;
		p++;
		c++;
	}
	return c;
}

static int pfxfmt(char *v) {
	int c;
	char *p;

	p = _llogbuf + _llogbuf_crsr;

	*p = '[';
	p++;
	_llogbuf_crsr++;

	c = cpy(v);
	p += c;
	
	*p = ']';
	c++;
	_llogbuf_crsr += c;
	
	return c+1;
}

static int lvlfmt(enum lloglvl_e lvl) {
	char *v;

	v = lloglvl_str[(int)lvl];

	return pfxfmt(v);
}

static char* kvstart(char *k) {
	char *p;
	int c;

	p = _llogbuf + _llogbuf_crsr;
	*p = 0x09;
	p++;

	_llogbuf_crsr++;
	c = cpy(k);
	p += c;
	*p = '=';
	c++;

	_llogbuf_crsr += c;

	return _llogbuf + _llogbuf_crsr;
}

char *llog_new(enum lloglvl_e lvl, char *msg) {
	char *p;
	int c;

	_llogbuf_crsr = 0;
	c = lvlfmt(lvl);
	p = _llogbuf + c;
	*p = ' ';
	p++;
	_llogbuf_crsr++;

	c = cpy(msg);
	_llogbuf_crsr += c;
	p += c;
	*p = 0;

	return _llogbuf;
}

char *llog_new_ns(enum lloglvl_e lvl, char *msg, char *ns) {
	char *p;
	int c;

	_llogbuf_crsr = 0;
	c = pfxfmt(ns);
	p = _llogbuf + c;
	c = lvlfmt(lvl);
	p += c;

	*p = ' ';
	p++;
	_llogbuf_crsr++;
	c = cpy(msg);

	_llogbuf_crsr += c;
	p += c;
	*p = 0;

	return _llogbuf;
}

char* llog_add_s(const char *k, char *v) {
	char *p;
	int c;

	p = kvstart((char*)k);
	c = 0;
	while (1) {
		if (*v == 0) {
			break;
		}
		*p = *v;
		p++;
		c++;
		v++;
	}

	_llogbuf_crsr += c;
	*p = 0;

	return _llogbuf;
}


char* llog_add_n(const char *k, long long v) {
	char *p;
	int c;
	char i;
	long long r;
	char *b;

	r = 0;
	p = kvstart((char*)k);
	c = 0;
	b = (char*)&r;
	b += (sizeof(r) - 1);
	while (v != 0) {
		i = v % 10;
		i += 0x30;
		*b = i;
		b--;
		c++;
		v /= 10;	
	}
	for (i = 0; i < c; i++) {
		b++;
		*p = *b;
		p++;
	}

	_llogbuf_crsr += c;
	*p = 0;

	return _llogbuf;
}

char* llog_add_x(const char *k, long long v) {
	char *p;
	int c;
	char i;
	char *b;

	p = kvstart((char*)k);
	c = 0;
	b = (char*)&v;
	b += (sizeof(v) - 1);

	i = 0;
	while (*b == 0 && i < 8) {
		b--;
		i++;
	}

	if (i == 8) {
		b++;
		i--;
	}
	*p = '0';
	p++;
	*p = 'x';
	p++;
	c = 2;
	for (; i < 8; i++) {
		c2h(*b, p);
		p += 2;
		c += 2;
		b--;
	}

	_llogbuf_crsr += c;
	*p = 0;

	return _llogbuf;
}


char* llog_add_b(const char *k, void *v, int l) {
	char *p;
	int c;

	c = 0;
	p = kvstart((char*)k);
	b2h(v, l, p);
	c += (l * 2);
	_llogbuf_crsr += c;
	p += c;
	*p = 0;

	return _llogbuf;
}
