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
	r = lq_config_register(LQ_TYP_STR);
	lq_config_free();
	ck_assert_int_eq(r, ERR_OK);
}
END_TEST

START_TEST(check_set_get) {
	int r;
	long v;
	char *p;

	lq_config_init();
	r = lq_config_register(LQ_TYP_NUM);
	ck_assert_int_eq(r, ERR_OK);
	r = lq_config_register(LQ_TYP_STR);
	ck_assert_int_eq(r, ERR_OK);

	r = lq_config_set(2, "foobarbaz");
	ck_assert_int_eq(r, ERR_OK);

	v = 42;
	r = lq_config_set(1, &v);
	ck_assert_int_eq(r, ERR_OK);

	r = lq_config_get(1, (void**)&p);
	ck_assert_int_eq(r, ERR_OK);
	v = *((long*)p);
	ck_assert_int_eq(v, 42);

	r = lq_config_get(2, (void**)&p);
	ck_assert_int_eq(r, ERR_OK);
	ck_assert_str_eq(p, "foobarbaz");

	r = lq_config_set(3, &v);
	ck_assert_int_eq(r, ERR_OVERFLOW);

	r = lq_config_get(3, (void**)&p);
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
