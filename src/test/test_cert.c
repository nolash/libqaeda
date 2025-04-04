#include <check.h>
#include <stdlib.h>
#include <string.h>

#include "lq/msg.h"
#include "lq/cert.h"
#include "lq/mem.h"
#include "lq/crypto.h"
#include "lq/config.h"
#include "lq/base.h"
#include "lq/io.h"

const char *data = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
const char *data_two = "Que trata de la condición y ejercicio del famoso hidalgo D. Quijote de la Mancha En un lugar de la Mancha, de cuyo nombre no quiero acordarme, no ha mucho tiempo que vivía un hidalgo de los de lanza en astillero, adarga antigua, rocín flaco y galgo corredor.";

//// sha256sum "foo" 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
//static const char privkeydata[32] = {
//	0x2c, 0x26, 0xb4, 0x6b, 0x68, 0xff, 0xc6, 0x8f,
//	0xf9, 0x9b, 0x45, 0x3c, 0x1d, 0x30, 0x41, 0x34,
//	0x13, 0x42, 0x2d, 0x70, 0x64, 0x83, 0xbf, 0xa0,
//	0xf9, 0x8a, 0x5e, 0x88, 0x62, 0x66, 0xe7, 0xae,
//};

// sha256sum "bar" fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9
static const char passphrase[32] = {
	0xfc, 0xde, 0x2b, 0x2e, 0xdb, 0xa5, 0x6b, 0xf4,
	0x08, 0x60, 0x1f, 0xb7, 0x21, 0xfe, 0x9b, 0x5c,
	0x33, 0x8d, 0x10, 0xee, 0x42, 0x9e, 0xa0, 0x4f,
	0xae, 0x55, 0x11, 0xb6, 0x8f, 0xbf, 0x8f, 0xb9,
};


START_TEST(check_cert_sig_req) {
	int r;
	size_t c;
	LQCert *cert;
	LQMsg *req;
	LQPrivKey *pk;
	LQPubKey *pubk;

	pk = lq_privatekey_new(passphrase, LQ_PRIVKEY_LEN);
	ck_assert_ptr_nonnull(pk);

	pubk = lq_publickey_from_privatekey(pk);
	ck_assert_ptr_nonnull(pubk);

	req = lq_msg_new("foo", 4);
	ck_assert_ptr_nonnull(req);

	cert = lq_certificate_new(NULL);
	ck_assert_ptr_nonnull(cert);
	r = lq_certificate_request(cert, req, pk);
	ck_assert_int_eq(r, 0);

	//res = lq_msg_new("barbaz", 7);
	//ck_assert_ptr_nonnull(res);
	//r = lq_certificate_respond(cert, res, pk_bob);
	//ck_assert_int_eq(r, 0);

	r = lq_certificate_verify(cert, pubk, NULL);
	ck_assert_int_eq(r, 0);

	lq_certificate_free(cert);
	lq_publickey_free(pubk);
	lq_privatekey_free(pk);
}
END_TEST

START_TEST(check_cert_symmetric_nomsg) {
	int r;
	size_t c;
	LQCert *cert;
	char buf[4096];

	cert = lq_certificate_new(NULL);
	c = 4096;
	r = lq_certificate_serialize(cert, buf, &c, NULL);
	ck_assert_int_eq(r, 0);
	lq_certificate_free(cert);

	r = lq_certificate_deserialize(&cert, buf, c, NULL);
	ck_assert_int_eq(r, 0);
	lq_certificate_free(cert);
}
END_TEST

START_TEST(check_cert_symmetric_req_nosig) {
	int r;
	size_t c;
	LQCert *cert;
	LQMsg *req;
	char buf[4096];

	req = lq_msg_new(data, strlen(data) + 1);
	cert = lq_certificate_new(NULL);
	r = lq_certificate_request(cert, req, NULL);
	c = 4096;
	r = lq_certificate_serialize(cert, buf, &c, NULL);
	ck_assert_int_eq(r, 0);
	lq_certificate_free(cert);

	r = lq_certificate_deserialize(&cert, buf, c, NULL);
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
	char buf[4096];

	pk = lq_privatekey_new(passphrase, 32);

	req = lq_msg_new(data, strlen(data) + 1);
	cert = lq_certificate_new(NULL);
	lq_privatekey_unlock(pk, passphrase, 32);
	r = lq_certificate_request(cert, req, pk);
	ck_assert_int_eq(r, 0);

	c = 4096;
	r = lq_certificate_serialize(cert, buf, &c, NULL);
	ck_assert_int_eq(r, 0);
	lq_certificate_free(cert);

	r = lq_certificate_deserialize(&cert, buf, c, NULL);
	ck_assert_int_eq(r, 0);
	lq_certificate_free(cert);
	lq_privatekey_free(pk);
}
END_TEST

START_TEST(check_cert_symmetric_rsp_onesig) {
	int r;
	size_t c;
	LQCert *cert;
	LQMsg *req;
	LQMsg *res;
	LQPrivKey *pk;
	char buf[4096];

	pk = lq_privatekey_new(passphrase, 32);
	req = lq_msg_new(data, strlen(data) + 1);
	res = lq_msg_new(data_two, strlen(data_two) + 1);
	cert = lq_certificate_new(NULL);
	lq_privatekey_unlock(pk, passphrase, 32);
	r = lq_certificate_request(cert, req, pk);
	ck_assert_int_eq(r, 0);

	c = 4096;
	r = lq_certificate_serialize(cert, buf, &c, NULL);
	ck_assert_int_eq(r, 0);
	lq_certificate_free(cert);

	r = lq_certificate_deserialize(&cert, buf, c, NULL);
	ck_assert_int_eq(r, 0);
	r = lq_certificate_respond(cert, res, pk);
	ck_assert_int_eq(r, 0);
	lq_certificate_free(cert);
	lq_privatekey_free(pk);
}
END_TEST

START_TEST(check_cert_symmetric_rsp_bothsig) {
	int r;
	size_t c;
	LQCert *cert;
	LQMsg *req;
	LQMsg *res;
	LQPrivKey *pk;
	char buf[4096];

	pk = lq_privatekey_new(passphrase, 32);
	req = lq_msg_new(data, strlen(data) + 1);
	ck_assert_ptr_nonnull(req);
	cert = lq_certificate_new(NULL);
	ck_assert_ptr_nonnull(cert);
	lq_privatekey_unlock(pk, passphrase, 32);
	r = lq_certificate_request(cert, req, NULL);
	r = lq_certificate_sign(cert, pk);
	ck_assert_int_eq(r, 0);

	res = lq_msg_new(data_two, strlen(data_two) + 1);
	ck_assert_ptr_nonnull(res);
	r = lq_certificate_respond(cert, res, NULL);
	ck_assert_int_eq(r, 0);
	r = lq_certificate_sign(cert, pk);
	ck_assert_int_eq(r, 0);

	c = 4096;
	r = lq_certificate_serialize(cert, buf, &c, NULL);
	ck_assert_int_eq(r, 0);
	lq_certificate_free(cert);

	r = lq_certificate_deserialize(&cert, buf, c, NULL);
	ck_assert_int_eq(r, 0);
	lq_certificate_free(cert);
}
END_TEST

Suite * common_suite(void) {
	Suite *s;
	TCase *tc;

	s = suite_create("cert");
	tc = tcase_create("sign");

	tcase_add_test(tc, check_cert_sig_req);
//	tcase_add_test(tc, check_cert_sig_res);

	tc = tcase_create("serialize");
//	tcase_add_test(tc, check_cert_symmetric_ser_nomsg);
//	tcase_add_test(tc, check_cert_symmetric_ser_req_nosig);
//	tcase_add_test(tc, check_cert_symmetric_ser_req_sig);
//	tcase_add_test(tc, check_cert_symmetric_ser_rsp_onesig);
//	tcase_add_test(tc, check_cert_symmetric_ser_rsp_bothsig);
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
