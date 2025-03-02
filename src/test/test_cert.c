#include <check.h>
#include <stdlib.h>
#include <string.h>

#include "lq/msg.h"
#include "lq/cert.h"
#include "lq/mem.h"
#include "lq/crypto.h"

const char *data = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
const char *data_two = "Que trata de la condición y ejercicio del famoso hidalgo D. Quijote de la Mancha En un lugar de la Mancha, de cuyo nombre no quiero acordarme, no ha mucho tiempo que vivía un hidalgo de los de lanza en astillero, adarga antigua, rocín flaco y galgo corredor.";


START_TEST(check_cert_symmetric_nomsg) {
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

	r = lq_certificate_deserialize(&cert, buf, c);
	ck_assert_int_eq(r, 0);
	lq_certificate_free(cert);
}
END_TEST

START_TEST(check_cert_symmetric_req_nosig) {
	int r;
	size_t c;
	LQCert *cert;
	LQMsg *req;
	LQCtx ctx;
	char buf[4096];

	lq_set(&ctx, 0, sizeof(LQCtx));
	req = lq_msg_new(data, strlen(data) + 1);
	cert = lq_certificate_new(NULL, &ctx, req, NULL);
	c = 4096;
	r = lq_certificate_serialize(cert, buf, &c);
	ck_assert_int_eq(r, 0);
	lq_certificate_free(cert);

	r = lq_certificate_deserialize(&cert, buf, c);
	ck_assert_int_eq(r, 0);
	lq_certificate_free(cert);
}
END_TEST

START_TEST(check_cert_symmetric_req_sig) {
	int r;
	size_t c;
	LQCert *cert;
	LQMsg *req;
	LQPrivKey *pk;
	LQCtx ctx;
	char buf[4096];

	pk = lq_privatekey_new(data, 32);
	lq_set(&ctx, 0, sizeof(LQCtx));
	req = lq_msg_new(data, strlen(data) + 1);
	cert = lq_certificate_new(NULL, &ctx, req, NULL);
	// \todo change interface to certificate sign
	r = lq_certificate_sign(cert, pk);
	ck_assert_int_eq(r, 0);

	c = 4096;
	r = lq_certificate_serialize(cert, buf, &c);
	ck_assert_int_eq(r, 0);
	lq_certificate_free(cert);

	r = lq_certificate_deserialize(&cert, buf, c);
	ck_assert_int_eq(r, 0);
	lq_certificate_free(cert);
}
END_TEST

START_TEST(check_cert_symmetric_rsp_onesig) {
	int r;
	size_t c;
	LQCert *cert;
	LQMsg *req;
	LQMsg *rsp;
	LQPrivKey *pk;
	LQCtx ctx;
	char buf[4096];

	pk = lq_privatekey_new(data, 32);
	lq_set(&ctx, 0, sizeof(LQCtx));
	req = lq_msg_new(data, strlen(data) + 1);
	rsp = lq_msg_new(data_two, strlen(data_two) + 1);
	cert = lq_certificate_new(NULL, &ctx, req, NULL);
	r = lq_certificate_sign(cert, pk);
	ck_assert_int_eq(r, 0);
	cert->response = rsp;

	c = 4096;
	r = lq_certificate_serialize(cert, buf, &c);
	ck_assert_int_eq(r, 0);
	lq_certificate_free(cert);

	r = lq_certificate_deserialize(&cert, buf, c);
	ck_assert_int_eq(r, 0);
	lq_certificate_free(cert);
}
END_TEST

START_TEST(check_cert_symmetric_rsp_bothsig) {
	int r;
	size_t c;
	LQCert *cert;
	LQMsg *req;
	LQPrivKey *pk;
	LQCtx ctx;
	char buf[4096];

	pk = lq_privatekey_new(data, 32);
	lq_set(&ctx, 0, sizeof(LQCtx));
	req = lq_msg_new(data, strlen(data) + 1);
	cert = lq_certificate_new(NULL, &ctx, req, NULL);
	r = lq_certificate_sign(cert, pk);
	ck_assert_int_eq(r, 0);

	cert->response = lq_msg_new(data_two, strlen(data_two) + 1);
	r = lq_certificate_sign(cert, pk);
	ck_assert_int_eq(r, 0);

	c = 4096;
	r = lq_certificate_serialize(cert, buf, &c);
	ck_assert_int_eq(r, 0);
	lq_certificate_free(cert);

	r = lq_certificate_deserialize(&cert, buf, c);
	ck_assert_int_eq(r, 0);
	lq_certificate_free(cert);
}
END_TEST

Suite * common_suite(void) {
	Suite *s;
	TCase *tc;

	s = suite_create("cert");
	tc = tcase_create("serialize");
	tcase_add_test(tc, check_cert_symmetric_nomsg);
	tcase_add_test(tc, check_cert_symmetric_req_nosig);
	tcase_add_test(tc, check_cert_symmetric_req_sig);
	tcase_add_test(tc, check_cert_symmetric_rsp_onesig);
	tcase_add_test(tc, check_cert_symmetric_rsp_bothsig);
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
