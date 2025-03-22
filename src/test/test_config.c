#include <stdlib.h>
#include <check.h>

#include "lq/err.h"
#include "lq/config.h"


START_TEST(check_core) {
	int r;

	r = lq_config_init();
	lq_config_free();
	ck_assert_int_eq(r, ERR_OK);
}
END_TEST

START_TEST(check_register) {
	int r;

	lq_config_init();
	r = lq_config_register(LQ_TYP_STR, NULL);
	lq_config_free();
	ck_assert_int_ge(r, 0);
}
END_TEST

START_TEST(check_set_get) {
	int r;
	long v;
	char *p;
	int c;

	c = LQ_CFG_LAST;
	lq_config_init();
	r = lq_config_register(LQ_TYP_NUM, NULL);
	ck_assert_int_ge(r, 0);
	r = lq_config_register(LQ_TYP_STR, NULL);
	ck_assert_int_ge(r, 0);

	// set with the index returned from the last register action
	r = lq_config_set(r, "foobarbaz");
	ck_assert_int_eq(r, ERR_OK);

	v = 42;
	r = lq_config_set(c, &v);
	ck_assert_int_eq(r, ERR_OK);

	r = lq_config_get(c, (void**)&p);
	ck_assert_int_eq(r, ERR_OK);
	v = *((long*)p);
	ck_assert_int_eq(v, 42);

	r = lq_config_get(c + 1, (void**)&p);
	ck_assert_int_eq(r, ERR_OK);
	ck_assert_str_eq(p, "foobarbaz");

	r = lq_config_set(c + 2, &v);
	ck_assert_int_eq(r, ERR_OVERFLOW);

	r = lq_config_get(c + 2, (void**)&p);
	ck_assert_int_eq(r, ERR_OVERFLOW);

	lq_config_free();
}
END_TEST

Suite * common_suite(void) {
	Suite *s;
	TCase *tc;

	s = suite_create("config");
	tc = tcase_create("core");
	tcase_add_test(tc, check_core);
	tcase_add_test(tc, check_register);
	tcase_add_test(tc, check_set_get);
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
