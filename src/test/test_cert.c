#include <check.h>
#include <stdlib.h>
#include <string.h>

#include "lq/msg.h"
#include "lq/cert.h"
#include "lq/mem.h"
#include "lq/crypto.h"

const char *data = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";


START_TEST(check_cert_symmetric) {
	int r;
	size_t c;
	LQCert *cert;
	LQCtx ctx;
	char buf[4096];

	lq_set(&ctx, 0, sizeof(LQCtx));
	cert = lq_certificate_new(NULL, &ctx, NULL, NULL);
	c = 4096;
	r = lq_certificate_serialize(cert, buf, &c);
	ck_assert_int_eq(r, 0);

	lq_certificate_free(cert);
}
END_TEST

Suite * common_suite(void) {
	Suite *s;
	TCase *tc;

	s = suite_create("cert");
	tc = tcase_create("serialize");
	tcase_add_test(tc, check_cert_symmetric);
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
