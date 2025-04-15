#include <check.h>
#include <stdlib.h>
#include <string.h>

#include <rerr.h>

#include "lq/crypto.h"
#include "lq/config.h"
#include "lq/io.h"
#include "lq/base.h"
#include "lq/err.h"


const char *data = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
const char *salt = "spamspamspamspamspamspamspamspam";

//// sha256sum "foo" 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
//static const char privkeydata[32] = {
//	0x2c, 0x26, 0xb4, 0x6b, 0x68, 0xff, 0xc6, 0x8f,
//	0xf9, 0x9b, 0x45, 0x3c, 0x1d, 0x30, 0x41, 0x34,
//	0x13, 0x42, 0x2d, 0x70, 0x64, 0x83, 0xbf, 0xa0,
//	0xf9, 0x8a, 0x5e, 0x88, 0x62, 0x66, 0xe7, 0xae,
//};

// "1234"
static const size_t passphrase_len = 4;
static const char passphrase[5] = {
	0x31, 0x32, 0x33, 0x34, 0x00,
};
// "11111"
static const size_t passphrase_two_len = 4;
static const char passphrase_two[6] = {
	0x31, 0x31, 0x31, 0x31, 0x31, 0x00,
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
	int r;
	char path[LQ_PATH_MAX];
	LQPrivKey *pk;

	lq_cpy(path, "/tmp/lqcrypto_test_XXXXXX", 26);
	r = lq_crypto_init(mktempdir(path));
	ck_assert_int_eq(r, ERR_OK);

	pk = lq_privatekey_new(passphrase, passphrase_len);
	ck_assert_ptr_nonnull(pk);
	lq_privatekey_free(pk);

	lq_crypto_free();
}
END_TEST

START_TEST(check_privatekey_lock) {
	int r;
	LQPrivKey *pk;

	pk = lq_privatekey_new(passphrase, passphrase_len);
	ck_assert_ptr_nonnull(pk);

	lq_privatekey_lock(pk, passphrase, passphrase_len);
	r = lq_privatekey_lock(pk, passphrase, passphrase_len);
	ck_assert_int_eq(r, ERR_NOOP);

	r = lq_privatekey_unlock(pk, passphrase, passphrase_len);
	ck_assert_int_eq(r, ERR_OK);

	r = lq_privatekey_unlock(pk, passphrase, passphrase_len);
	ck_assert_int_eq(r, ERR_NOOP);

	r = lq_privatekey_lock(pk, passphrase, passphrase_len);
	ck_assert_int_eq(r, ERR_OK);

	r = lq_privatekey_lock(pk, passphrase, passphrase_len);
	ck_assert_int_eq(r, ERR_NOOP);

	lq_privatekey_free(pk);
}
END_TEST

START_TEST(check_publickey) {
	int r;
	char path[LQ_PATH_MAX];
	LQPrivKey *pk;
	LQPubKey *pubk;
	LQPubKey *pubk_manual;
	char *keydata;
	char *keydata_manual;

	lq_cpy(path, "/tmp/lqcrypto_test_XXXXXX", 26);
	r = lq_crypto_init(mktempdir(path));
	ck_assert_int_eq(r, ERR_OK);

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

	lq_crypto_free();
}
END_TEST

START_TEST(check_signature) {
	int r;
	char path[LQ_PATH_MAX];
	char digest[32];
	LQPrivKey *pk;
	LQSig *sig;
	char *sigdata;

	lq_cpy(path, "/tmp/lqcrypto_test_XXXXXX", 26);
	r = lq_crypto_init(mktempdir(path));
	ck_assert_int_eq(r, ERR_OK);

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

	lq_crypto_free();
}
END_TEST

START_TEST(check_verify) {
	int r;
	char path[LQ_PATH_MAX];
	LQPrivKey *pk;
	LQSig *sig;

	lq_cpy(path, "/tmp/lqcrypto_test_XXXXXX", 26);
	r = lq_crypto_init(mktempdir(path));
	ck_assert_int_eq(r, ERR_OK);

	pk = lq_privatekey_new(passphrase, 32);
	ck_assert_ptr_nonnull(pk);
	sig = lq_privatekey_sign(pk, data, strlen(data), salt);
	ck_assert_ptr_null(sig);

	r = lq_privatekey_unlock(pk, passphrase, 32);
	ck_assert_int_eq(r, 0);

	sig = lq_privatekey_sign(pk, data, strlen(data), salt);
	ck_assert_ptr_nonnull(sig);

	r = lq_signature_verify(sig, data, strlen(data));
	ck_assert_int_eq(r, 0);

	lq_signature_free(sig);
	lq_privatekey_free(pk);

	lq_crypto_free();
}
END_TEST

START_TEST(check_create_load) {
	int r;
	char path[LQ_PATH_MAX];
	LQPrivKey *pk;
	LQPrivKey *pk_load;

	lq_cpy(path, "/tmp/lqcrypto_test_XXXXXX", 26);
	r = lq_crypto_init(mktempdir(path));
	ck_assert_int_eq(r, ERR_OK);

	pk = lq_privatekey_new(passphrase, passphrase_len);
	ck_assert_ptr_nonnull(pk);
	pk_load = lq_privatekey_load(passphrase, passphrase_len, NULL);
	ck_assert_ptr_nonnull(pk_load);

	lq_privatekey_free(pk);

	lq_crypto_free();
}
END_TEST

START_TEST(check_load_specific) {
	int r;
	char path[LQ_PATH_MAX];
	LQPrivKey *pk;
	LQPubKey *pubk;
	LQPrivKey *pk_load;
	char *p;
	size_t c;

	lq_cpy(path, "/tmp/lqcrypto_test_XXXXXX", 26);
	r = lq_crypto_init(mktempdir(path));
	ck_assert_int_eq(r, ERR_OK);

	pk = lq_privatekey_new(passphrase, passphrase_len);
	ck_assert_ptr_nonnull(pk);
	pubk = lq_publickey_from_privatekey(pk);
	ck_assert_ptr_nonnull(pubk);
	c = lq_publickey_fingerprint(pubk, &p);
	ck_assert_int_gt(c, 0);
	//pk_load = lq_privatekey_load(passphrase, passphrase_len, NULL);
	//ck_assert_ptr_nonnull(pk_load);
	pk_load = lq_privatekey_load(passphrase, passphrase_len, p);
	ck_assert_ptr_nonnull(pk_load);

	lq_privatekey_free(pk);

	lq_crypto_free();
}
END_TEST

START_TEST(check_many) {
	int r;
	char path[LQ_PATH_MAX];
	LQPrivKey *pk;
	LQPubKey *pubk;
	LQPubKey *pubk_manual;
	char *keydata;
	char *keydata_manual;

	lq_cpy(path, "/tmp/lqcrypto_test_XXXXXX", 26);
	r = lq_crypto_init(mktempdir(path));
	ck_assert_int_eq(r, ERR_OK);

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

	lq_crypto_free();
}
END_TEST

START_TEST(check_open_more) {
	int r;
	char path[LQ_PATH_MAX];
	LQPrivKey *pk_alice;
	LQPrivKey *pk_bob;
	LQPubKey *pubk_before;
	LQPubKey *pubk_before_bob;
	LQPubKey *pubk_after;
	char *fp_alice;
	char *fp_bob;

	lq_cpy(path, "/tmp/lqcrypto_test_XXXXXX", 26);
	r = lq_crypto_init(mktempdir(path));
	ck_assert_int_eq(r, ERR_OK);

	// create alice keypair
	pk_alice = lq_privatekey_new(passphrase, passphrase_len);
	ck_assert_ptr_nonnull(pk_alice);
	pubk_before = lq_publickey_from_privatekey(pk_alice);
	r = lq_publickey_fingerprint(pubk_before, &fp_alice);
	ck_assert_int_eq(r, LQ_FP_LEN);
	lq_privatekey_free(pk_alice);

	// create bob keypair
	pk_bob = lq_privatekey_new(passphrase_two, passphrase_two_len);
	ck_assert_ptr_nonnull(pk_bob);
	pubk_before_bob = lq_publickey_from_privatekey(pk_bob);
	r = lq_publickey_fingerprint(pubk_before_bob, &fp_bob);
	ck_assert_int_eq(r, LQ_FP_LEN);

	// load alice key as default and check match public key from create
	pk_alice = lq_privatekey_load(passphrase, passphrase_len, NULL);
	ck_assert_ptr_nonnull(pk_alice);
	pubk_after = lq_publickey_from_privatekey(pk_alice);
	ck_assert_int_eq(lq_publickey_match(pubk_before, pubk_after), ERR_OK);
	lq_publickey_free(pubk_after);
	lq_privatekey_free(pk_alice);

	// load alice key explicit and check match public key from create
	pk_alice = lq_privatekey_load(passphrase, passphrase_len, fp_alice);
	ck_assert_ptr_nonnull(pk_alice);
	pubk_after = lq_publickey_from_privatekey(pk_alice);
	ck_assert_int_eq(lq_publickey_match(pubk_before, pubk_after), ERR_OK);
	lq_publickey_free(pubk_after);

	// load bob key explicit and check match public key from create
	pubk_after = lq_publickey_from_privatekey(pk_bob);
	r = lq_publickey_fingerprint(pubk_after, &fp_bob);
	ck_assert_int_eq(r, LQ_FP_LEN);
	ck_assert_int_ne(lq_publickey_match(pubk_before, pubk_after), ERR_OK);
	ck_assert_int_eq(lq_publickey_match(pubk_before_bob, pubk_after), ERR_OK);

	lq_publickey_free(pubk_after);
	lq_publickey_free(pubk_before_bob);
	lq_publickey_free(pubk_before);

	lq_privatekey_free(pk_bob);
	lq_privatekey_free(pk_alice);

	lq_crypto_free();
}
END_TEST

Suite * common_suite(void) {
	Suite *s;
	TCase *tc;

	s = suite_create("crypto");
	tc = tcase_create("file");
	tcase_add_test(tc, check_digest);
	tcase_add_test(tc, check_privatekey);
	tcase_add_test(tc, check_privatekey_lock);
	tcase_add_test(tc, check_publickey);
	tcase_add_test(tc, check_signature);
	tcase_add_test(tc, check_verify);
	tcase_add_test(tc, check_create_load);
	tcase_add_test(tc, check_load_specific);
	tcase_add_test(tc, check_many);
	tcase_add_test(tc, check_open_more);
	suite_add_tcase(s, tc);

	return s;
}

int main(void) {
	int r;
	int n_fail;

	Suite *s;
	SRunner *sr;

	r = lq_init();
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
