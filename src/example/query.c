#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <lq/store.h>
#include <lq/query.h>
#include <lq/mem.h>
#include <lq/io.h>
#include <lq/err.h>


int main(int argc, char **argv) {
	int r;
	char *p;
	char path[PATH_MAX];
	LQStore *store;
	LQQuery *query;

	if (argc < 2) {
		return 1;
	}

	if (argc > 2) {
		strcpy(path, *(argv+2));
	} else {
		memcpy(path, "./out/", 6);
	}
	ensuredir(path);
	store = lq_store_new(path);

	p = *(argv+1);
	query = lq_query_new(LQ_CONTENT_RAW, store, p, strlen(p));
	if (query == NULL) {
		return ENOENT;
	}

	while(lq_query_next(query) == ERR_OK) {
		printf("have\n");
	}

	lq_query_free(query);
	lq_store_free(store);
	return 0;
}
