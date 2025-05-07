#include <check.h>
#include <stdlib.h>
#include <string.h>

#include "lq/store.h"
#include "lq/mem.h"
#include "lq/query.h"
#include "lq/io.h"
#include "lq/err.h"

extern LQStore LQFileContent;

/**
 * \todo DRY file store dir creation
 */
START_TEST(check_query_full) {
	int r;
	LQStore store;
	char path[LQ_PATH_MAX];
	char *k;
	char *v;
	size_t kl;
	size_t vl;
	LQQuery *query;

	lq_cpy(&store, &LQFileContent, sizeof(LQStore));
	lq_cpy(path, "/tmp/lqstore_file_XXXXXX", 25);
	store.userdata = mktempdir(path);
	*((char*)(store.userdata+24)) = '/';
	*((char*)(store.userdata+25)) = 0x0;

	k = "aaa";
	v = "foo";
	kl = 3;
	vl = 3;
	store.put(LQ_CONTENT_RAW, &store, k, &kl, v, vl);

	k = "aab";
	v = "bar";
	kl = 3;
	vl = 3;
	store.put(LQ_CONTENT_RAW, &store, k, &kl, v, vl);

	k = "aaa";
	v = "inky";
	kl = 3;
	vl = 4;
	store.put(LQ_CONTENT_MSG, &store, k, &kl, v, vl);

	k = "aab";
	v = "pinky";
	kl = 3;
	vl = 5;
	store.put(LQ_CONTENT_MSG, &store, k, &kl, v, vl);

	k = "aac";
	v = "blinky";
	kl = 3;
	vl = 6;
	store.put(LQ_CONTENT_MSG, &store, k, &kl, v, vl);

	k = "bbc";
	v = "clyde";
	kl = 3;
	vl = 5;
	store.put(LQ_CONTENT_MSG, &store, k, &kl, v, vl);

	k = "bbc";
	v = "clyde";
	kl = 3;
	vl = 5;
	store.put(LQ_CONTENT_CERT, &store, k, &kl, v, vl);

	query = lq_query_new(LQ_CONTENT_RAW, &store, "aa", 2);
	ck_assert_ptr_nonnull(query);

	r = lq_query_next(query);
	ck_assert_int_eq(r, ERR_OK);
	r = lq_query_next(query);
	ck_assert_int_eq(r, ERR_OK);
	r = lq_query_next(query);
	ck_assert_int_eq(r, ERR_OK | ERR_EOF);
	lq_query_free(query);

	query = lq_query_new(LQ_CONTENT_MSG, &store, "aa", 2);
	ck_assert_ptr_nonnull(query);

	r = lq_query_next(query);
	ck_assert_int_eq(r, ERR_OK);
	r = lq_query_next(query);
	ck_assert_int_eq(r, ERR_OK);
	r = lq_query_next(query);
	ck_assert_int_eq(r, ERR_OK);
	r = lq_query_next(query);
	ck_assert_int_eq(r, ERR_OK | ERR_EOF);

	k = lq_query_get_key(query);
	kl = lq_query_get_key_len(query);
	ck_assert_int_eq(kl, 3);
	ck_assert_mem_eq(k, "aac", kl);

	v = lq_query_get_val(query);
	vl = lq_query_get_val_len(query);
	ck_assert_int_eq(vl, 6);
	ck_assert_mem_eq(v, "blinky", vl);

	lq_query_free(query);
}
END_TEST

Suite * common_suite(void) {
	Suite *s;
	TCase *tc;

	s = suite_create("query");
	tc = tcase_create("files");
	tcase_add_test(tc, check_query_full);
	suite_add_tcase(s, tc);

	return s;
}

int main(void) {
	int n_fail;

	Suite *s;
	SRunner *sr;

	s = common_suite();	
	sr = srunner_create(s);

	srunner_run_all(sr, CK_VERBOSE);
	n_fail = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (n_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
