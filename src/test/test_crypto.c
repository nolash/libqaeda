#include <check.h>
#include <stdlib.h>
#include <string.h>

#include "lq/crypto.h"


const char *data = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
const char salt[4] = {0xde, 0xad, 0xbe, 0xef};

START_TEST(check_digest) {
	int r;
	char out[32];

	r = lq_digest(data, strlen(data), (char*)out);
	ck_assert(r == 0);
}
END_TEST

START_TEST(check_publickey) {
	LQPrivKey *pk;
	LQPubKey *pubk;
	LQPubKey *pubk_manual;

	pk = lq_privatekey_new(data, 32);
	pubk = lq_publickey_from_privatekey(pk);
	pubk_manual = lq_publickey_new(pubk->lokey);
	ck_assert_mem_eq(pubk_manual->lokey, pubk->lokey, 65);
	lq_publickey_free(pubk_manual);
	lq_publickey_free(pubk);
	lq_privatekey_free(pk);
}
END_TEST

START_TEST(check_signature) {
	LQPrivKey *pk;
	LQSig *sig;

	pk = lq_privatekey_new(data, 32);
	sig = lq_privatekey_sign(pk, data, strlen(data), salt, 4);

	ck_assert_char_eq(*(sig+64), 0x2a);
}
END_TEST

Suite * common_suite(void) {
	Suite *s;
	TCase *tc;

	s = suite_create("crypto");
	tc = tcase_create("dummy");
	tcase_add_test(tc, check_digest);
	tcase_add_test(tc, check_publickey);
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
