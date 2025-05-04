#ifndef LIBQAEDA_QUERY_H_
#define LIBQAEDA_QUERY_H_

enum lq_query_state_e {
	LQ_QUERY_EMPTY = 0,
	LQ_QUERY_READY = 1,
	LQ_QUERY_GONER = 2,
	LQ_QUERY_EOF = 4,
};

typedef struct lq_query_t LQQuery;
struct lq_query_t {
	LQStore *store;
	enum payload_e typ;
	int state;
	char **files;
	size_t files_len;
	size_t files_cur;
	char *value;
	size_t value_len;
};

LQQuery* lq_query_new(enum payload_e typ, LQStore *store, const char *key, size_t key_len);
int lq_query_next(LQQuery *query);
void lq_query_free(LQQuery *query);

#endif // LIBQAEDA_QUERY_H_
