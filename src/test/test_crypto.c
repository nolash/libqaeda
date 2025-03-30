#include <check.h>
#include <stdlib.h>
#include <string.h>

#include "lq/crypto.h"
#include "lq/config.h"
#include "lq/io.h"
#include "lq/base.h"


const char *data = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
const char *salt = "spamspamspamspamspamspamspamspam";

//// sha256sum "foo" 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
//static const char privkeydata[32] = {
//	0x2c, 0x26, 0xb4, 0x6b, 0x68, 0xff, 0xc6, 0x8f,
//	0xf9, 0x9b, 0x45, 0x3c, 0x1d, 0x30, 0x41, 0x34,
//	0x13, 0x42, 0x2d, 0x70, 0x64, 0x83, 0xbf, 0xa0,
//	0xf9, 0x8a, 0x5e, 0x88, 0x62, 0x66, 0xe7, 0xae,
//};

// "1233"
static const size_t passphrase_len = 4;
static const char passphrase[5] = {
	0x31, 0x32, 0x33, 0x34, 0x00,
};


struct dummycrypto {
	void *data; ///< Literal private key data.
	size_t len; ///< Length of private key data.
};

START_TEST(check_digest) {
	int r;
	char out[LQ_DIGEST_LEN];

	r = lq_digest(data, strlen(data), (char*)out);
	ck_assert(r == 0);
}
END_TEST

START_TEST(check_privatekey) {
	LQPrivKey *pk;

	pk = lq_privatekey_new(passphrase, passphrase_len);
	ck_assert_ptr_nonnull(pk);
	lq_privatekey_free(pk);
}
END_TEST

START_TEST(check_publickey) {
	LQPrivKey *pk;
	LQPubKey *pubk;
	LQPubKey *pubk_manual;
	char *keydata;
	char *keydata_manual;

	pk = lq_privatekey_new(passphrase, passphrase_len);
	ck_assert_ptr_nonnull(pk);
	pubk = lq_publickey_from_privatekey(pk);
	lq_publickey_bytes(pubk, &keydata);
	pubk_manual = lq_publickey_new(keydata);
	lq_publickey_bytes(pubk_manual, &keydata_manual);
	ck_assert_mem_eq(keydata_manual, keydata, 65);
	lq_publickey_free(pubk_manual);
	lq_publickey_free(pubk);
	lq_privatekey_free(pk);
}
END_TEST

START_TEST(check_signature) {
	char r;
	char digest[32];
	LQPrivKey *pk;
	LQSig *sig;
	char *sigdata;

	pk = lq_privatekey_new(passphrase, passphrase_len);
	ck_assert_ptr_nonnull(pk);
	sig = lq_privatekey_sign(pk, data, strlen(data), salt);
	ck_assert_ptr_null(sig);

	r = lq_privatekey_unlock(pk, passphrase, 32);
	ck_assert_int_eq(r, 0);

	sig = lq_privatekey_sign(pk, digest, 32, salt);
	ck_assert_ptr_nonnull(sig);

	r = lq_signature_bytes(sig, &sigdata);
	ck_assert_mem_eq(sig->impl, sigdata, r);

	lq_signature_free(sig);
	lq_privatekey_free(pk);
}
END_TEST

START_TEST(check_verify) {
	char r;
	LQPrivKey *pk;
	LQSig *sig;

	pk = lq_privatekey_new(passphrase, 32);
	ck_assert_ptr_nonnull(pk);
	sig = lq_privatekey_sign(pk, data, strlen(data), salt);
	ck_assert_ptr_null(sig);

	r = lq_privatekey_unlock(pk, passphrase, 32);
	ck_assert_int_eq(r, 0);

	sig = lq_privatekey_sign(pk, data, strlen(data), salt);
	ck_assert_ptr_nonnull(sig);

	r = lq_signature_verify(sig, data, strlen(data));

	lq_signature_free(sig);
	lq_privatekey_free(pk);
}
END_TEST

START_TEST(check_create_load) {
	LQPrivKey *pk;
	LQPrivKey *pk_load;

	pk = lq_privatekey_new(passphrase, passphrase_len);
	ck_assert_ptr_nonnull(pk);
	pk_load = lq_privatekey_load(passphrase, passphrase_len, NULL);
	ck_assert_ptr_nonnull(pk_load);

	lq_privatekey_free(pk);
}
END_TEST

START_TEST(check_load_specific) {
	LQPrivKey *pk;
	LQPubKey *pubk;
	LQPrivKey *pk_load;
	char *p;
	size_t c;

	pk = lq_privatekey_new(passphrase, passphrase_len);
	ck_assert_ptr_nonnull(pk);
	pubk = lq_publickey_from_privatekey(pk);
	ck_assert_ptr_nonnull(pubk);
	c = lq_publickey_fingerprint(pubk, &p);
	ck_assert_int_gt(c, 0);
	pk_load = lq_privatekey_load(passphrase, passphrase_len, NULL);
	ck_assert_ptr_nonnull(pk_load);
	pk_load = lq_privatekey_load(passphrase, passphrase_len, p);
	ck_assert_ptr_nonnull(pk_load);

	lq_privatekey_free(pk);
}
END_TEST

Suite * common_suite(void) {
	Suite *s;
	TCase *tc;

	s = suite_create("crypto");
	tc = tcase_create("file");
	tcase_add_test(tc, check_digest);
	tcase_add_test(tc, check_privatekey);
	tcase_add_test(tc, check_publickey);
	tcase_add_test(tc, check_signature);
	tcase_add_test(tc, check_verify);
	tcase_add_test(tc, check_create_load);
	tcase_add_test(tc, check_load_specific);
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

	lq_crypto_free();

	return (n_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
