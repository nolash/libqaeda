#include <check.h>
#include <stdlib.h>

#include "debug.h"

START_TEST(check_debug_novar) {
	debug_dbg("test", "foo");
	debug_dbg_x("test", "foo", 1, MORGEL_TYP_STR, 0, "bar", "baz");
	debug_dbg_x("test", "foo", 1, MORGEL_TYP_BIN, 3, "inky", "pinky");
	debug_dbg_x("test", "foo", 1, MORGEL_TYP_NUM, 0, "xyzzy", 42);
}
END_TEST

Suite * common_suite(void) {
	Suite *s;
	TCase *tc;

	s = suite_create("debug");
	tc = tcase_create("touch");
	tcase_add_test(tc, check_debug_novar);
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
