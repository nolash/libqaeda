#include <check.h>
#include <stdlib.h>
#include <string.h>

#include "lq/crypto.h"


const char *data = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
const char *salt = "spamspamspamspamspamspamspamspam";

// sha256sum "foo" 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
static const char privkeydata[32] = {
	0x2c, 0x26, 0xb4, 0x6b, 0x68, 0xff, 0xc6, 0x8f,
	0xf9, 0x9b, 0x45, 0x3c, 0x1d, 0x30, 0x41, 0x34,
	0x13, 0x42, 0x2d, 0x70, 0x64, 0x83, 0xbf, 0xa0,
	0xf9, 0x8a, 0x5e, 0x88, 0x62, 0x66, 0xe7, 0xae,
};

// sha256sum "bar" fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9
static const char passphrase[32] = {
	0xfc, 0xde, 0x2b, 0x2e, 0xdb, 0xa5, 0x6b, 0xf4,
	0x08, 0x60, 0x1f, 0xb7, 0x21, 0xfe, 0x9b, 0x5c,
	0x33, 0x8d, 0x10, 0xee, 0x42, 0x9e, 0xa0, 0x4f,
	0xae, 0x55, 0x11, 0xb6, 0x8f, 0xbf, 0x8f, 0xb9,
};

struct dummycrypto {
	void *data; ///< Literal private key data.
	size_t len; ///< Length of private key data.
};


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
	char *keydata;
	char *keydata_manual;

	pk = lq_privatekey_new(privkeydata, 32);
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

	pk = lq_privatekey_new(privkeydata, 32);
	lq_digest(data, strlen(data), (char*)digest);
	sig = lq_privatekey_sign(pk, digest, 32, salt);
	ck_assert_ptr_null(sig);

	r = lq_privatekey_unlock(pk, passphrase);
	ck_assert_int_eq(r, 0);

	sig = lq_privatekey_sign(pk, digest, 32, salt);
	ck_assert_ptr_nonnull(sig);

	r = 42;
	lq_signature_bytes(sig, &sigdata);
	ck_assert_mem_eq(sigdata+65, &r, 1);

	lq_signature_free(sig);
	lq_privatekey_free(pk);
}
END_TEST

Suite * common_suite(void) {
	Suite *s;
	TCase *tc;

	s = suite_create("crypto");
	tc = tcase_create("dummy");
	tcase_add_test(tc, check_digest);
	tcase_add_test(tc, check_publickey);
	tcase_add_test(tc, check_signature);
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
