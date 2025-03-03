#include <check.h>
#include <stdlib.h>

#include "lq/trust.h"
#include "lq/store.h"
#include "lq/err.h"


START_TEST(check_trust_none) {
}
END_TEST

START_TEST(check_trust_one) {
}
END_TEST

START_TEST(check_trust_best) {
}
END_TEST

START_TEST(check_trust_all) {
}
END_TEST

Suite * common_suite(void) {
	Suite *s;
	TCase *tc;

	s = suite_create("trust");
	tc = tcase_create("check");
	tcase_add_test(tc, check_trust_none);
	tcase_add_test(tc, check_trust_one);
	tcase_add_test(tc, check_trust_best);
	tcase_add_test(tc, check_trust_all);
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
