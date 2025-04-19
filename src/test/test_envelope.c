#include <check.h>
#include <stdlib.h>
#include <string.h>

//#include "lq/msg.h"
#include "lq/cert.h"
#include "lq/mem.h"
//#include "lq/crypto.h"
#include "lq/config.h"
#include "lq/base.h"
#include "lq/envelope.h"
#include "lq/io.h"

const char *data = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
const char *data_two = "Que trata de la condición y ejercicio del famoso hidalgo D. Quijote de la Mancha En un lugar de la Mancha, de cuyo nombre no quiero acordarme, no ha mucho tiempo que vivía un hidalgo de los de lanza en astillero, adarga antigua, rocín flaco y galgo corredor.";

START_TEST(check_envelope) {
	int r;
	size_t c;
	LQCert *cert;
	LQEnvelope *env;
	LQMsg *req;
	char buf[4096];

	req = lq_msg_new(data, strlen(data) + 1);
	ck_assert_ptr_nonnull(req);

	cert = lq_certificate_new(NULL);
	ck_assert_ptr_nonnull(cert);

	r = lq_certificate_request(cert, req, NULL);
	c = LQ_BLOCKSIZE;
	r = lq_certificate_serialize(cert, NULL, buf, &c);
	ck_assert_int_eq(r, 0);

	env = lq_envelope_new(cert, 0);
	ck_assert_ptr_nonnull(env);
	r = lq_envelope_attach(env, data, strlen(data) + 1);
	ck_assert_int_eq(r, 0);
	r = lq_envelope_attach(env, data_two, strlen(data_two) + 1);
	ck_assert_int_eq(r, 0);

	c = sizeof(buf);
	r = lq_envelope_serialize(env, NULL, buf, &c);
	ck_assert_int_eq(r, 0);

	lq_envelope_free(env);
}
END_TEST


Suite * common_suite(void) {
	Suite *s;
	TCase *tc;

	s = suite_create("envelope");
	tc = tcase_create("serialize");
	tcase_add_test(tc, check_envelope);
	suite_add_tcase(s, tc);

	return s;
}

int main(void) {
	int r;
	int n_fail;
	char path[LQ_PATH_MAX];

	Suite *s;
	SRunner *sr;

	r = lq_init();
	if (r) {
		return 1;
	}

	lq_cpy(path, "/tmp/lqcrypto_test_XXXXXX", 26);
	r = lq_crypto_init(mktempdir(path));
	if (r) {
		return 1;
	}

	s = common_suite();	
	sr = srunner_create(s);

	srunner_run_all(sr, CK_VERBOSE);
	n_fail = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (n_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
