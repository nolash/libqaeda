#include <check.h>
#include <stdlib.h>
#include <string.h>

#include "lq/crypto.h"



START_TEST(check_digest) {
	int r;
	const char *data = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
	char out[32];

	r = lq_digest(data, strlen(data), (char*)out);
	ck_assert(r == 0);
	
}
END_TEST

Suite * common_suite(void) {
	Suite *s;
	TCase *tc;

	s = suite_create("crypto");
	tc = tcase_create("dummy");
	tcase_add_test(tc, check_digest);
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
