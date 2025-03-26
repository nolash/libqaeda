#include <check.h>
#include <stdlib.h>
#include <string.h>

#include <lq/store.h>
#include <lq/mem.h>


extern LQStore LQFileContent;

START_TEST(check_store_count) {
	int r;
	LQStore store;

	lq_cpy(&store, &LQFileContent, sizeof(LQStore));
	store.userdata = "./testdata";

	r = store.count(LQ_CONTENT_MSG, &store, "aa", 2);

	ck_assert_int_eq(r, 2);
}
END_TEST

Suite * common_suite(void) {
	Suite *s;
	TCase *tc;

	s = suite_create("store");
	tc = tcase_create("files");
	tcase_add_test(tc, check_store_count);
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
