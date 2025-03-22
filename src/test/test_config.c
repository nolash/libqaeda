#include <stdlib.h>
#include <check.h>

#include "lq/err.h"
#include "lq/config.h"


START_TEST(check_core) {
	int r;

	r = lq_config_init();
	ck_assert_int_eq(r, ERR_OK);
}
END_TEST

Suite * common_suite(void) {
	Suite *s;
	TCase *tc;

	s = suite_create("config");
	tc = tcase_create("core");
	tcase_add_test(tc, check_core);
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
