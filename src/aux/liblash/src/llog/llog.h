#ifndef LLOG_H_
#define LLOG_H_

#define LLOG_LENGTH 1024

#ifndef LLOG_DEFAULT_NS
#define LLOG_DEFAULT_NS "llog"
#endif

enum lloglvl_e {
	LLOG_NONE = 0,
	LLOG_CRITICAL,
	LLOG_ERROR,
	LLOG_WARNING,
	LLOG_INFO,
	LLOG_DEBUG,
	LLOG_GURU,
	LLOG_USR,
	LLOG_N_LEVELS,
};

char* llog_new(enum lloglvl_e lvl, char *msg);
char* llog_new_ns(enum lloglvl_e lvl, char *msg, char *ns);
char* llog_add_s(const char *k, char *v);
char* llog_add_n(const char *k, long long v);
char* llog_add_x(const char *k, long long v);
char* llog_add_b(const char *k, void *v, int l);
extern void llog_out(const char *v);

#endif
