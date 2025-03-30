#include <check.h>
#include <stdlib.h>

#include "lq/trust.h"
#include "lq/store.h"
#include "lq/err.h"
#include "lq/mem.h"
#include "lq/crypto.h"
#include "lq/io.h"

static const char pubkey_data_alice[65] = { 0x40,
	0xde, 0x58, 0x08, 0xe7, 0x24, 0x5e, 0x04, 0x72,
	0x7d, 0xb3, 0x83, 0xe4, 0x28, 0x76, 0xfc, 0x02, 
	0x91, 0xb7, 0xac, 0x31, 0xda, 0x65, 0x9a, 0xc9,
	0x80, 0x72, 0xb7, 0x14, 0x87, 0x36, 0x90, 0x29,
	0x0c, 0x0e, 0xca, 0x23, 0xa7, 0xb2, 0xc1, 0x38,
	0x75, 0x97, 0x41, 0xea, 0x6c, 0xb4, 0xfc, 0x71,
	0x91, 0x7a, 0xa6, 0x9f, 0x04, 0xb3, 0x95, 0x10,
	0x8b, 0x42, 0xd6, 0x26, 0x10, 0x64, 0x8c, 0xdb,
};

static const unsigned char trust_alice[2] = {
	0x01, 0x78,
};

static const char pubkey_data_bob[65] = {
	0x40, 
	0x79, 0x28, 0x14, 0x6b, 0xb3, 0x19, 0x19, 0xfc,
	0xab, 0xb3, 0x23, 0xa3, 0x8b, 0x36, 0xfe, 0x36,
	0x33, 0xd7, 0x29, 0x62, 0x6a, 0x2f, 0x1d, 0x11,
	0x01, 0x77, 0x93, 0x2e, 0x00, 0xc7, 0x80, 0x8d,
	0xaf, 0x17, 0xa1, 0xe2, 0x62, 0xe8, 0xe3, 0xb3,
	0xe0, 0x34, 0x33, 0x88, 0xc8, 0x13, 0xe5, 0x52,
	0x07, 0x27, 0xfe, 0x4b, 0xa7, 0x9c, 0xa9, 0x45,
	0x6c, 0x4d, 0x14, 0x2a, 0x70, 0xec, 0x07, 0x80,
};

static const unsigned char trust_bob[2] = {
	0x00, 0x40,
};

extern LQStore LQMemContent;

START_TEST(check_trust_none) {
	int r;
	unsigned char flag_test[2];
	LQPubKey *pubkey_alice;
	LQPubKey *pubkey_bob;
	LQStore *store;
	char *lodata;
	size_t lolen;
	char path[1024];
	char *p;

	lq_cpy(path, "/tmp/lqstore_file_XXXXXX", 25);
	p = mktempdir(path);
	*(p+24) = '/';
	*(p+25) = 0x0;
	store = lq_store_new(p);
	ck_assert_ptr_nonnull(store->userdata);

	pubkey_alice = lq_publickey_new(pubkey_data_alice);
	pubkey_bob = lq_publickey_new(pubkey_data_bob);

	lolen = lq_publickey_bytes(pubkey_alice, &lodata);
	store->put(LQ_CONTENT_KEY, store, lodata, &lolen, (char*)trust_alice, 2);

	lq_set(flag_test, 0, 2); 
	r = lq_trust_check(pubkey_alice, store, TRUST_MATCH_NONE, flag_test);
	ck_assert_int_eq(r, 1000000);

	r = lq_trust_check(pubkey_bob, store, TRUST_MATCH_NONE, flag_test);
	ck_assert_int_eq(r, -1);

	lolen = lq_publickey_bytes(pubkey_bob, &lodata);
	store->put(LQ_CONTENT_KEY, store, lodata, &lolen, (char*)trust_bob, 2);
	r = lq_trust_check(pubkey_bob, store, TRUST_MATCH_NONE, flag_test);
	ck_assert_int_eq(r, 1000000);

	store->free(store);
}
END_TEST

START_TEST(check_trust_one) {
	int r;
	unsigned char flag_test[2];
	LQPubKey *pubkey_alice;
	LQStore *store;
	char *lodata;
	size_t lolen;
	char path[1024];
	char *p;

	lq_cpy(path, "/tmp/lqstore_file_XXXXXX", 25);
	p = mktempdir(path);
	*(p+24) = '/';
	*(p+25) = 0x0;
	store = lq_store_new(p);
	ck_assert_ptr_nonnull(store->userdata);

	pubkey_alice = lq_publickey_new(pubkey_data_alice);

	lolen = lq_publickey_bytes(pubkey_alice, &lodata);
	store->put(LQ_CONTENT_KEY, store, lodata, &lolen, (char*)trust_alice, 2);

	flag_test[0] = 0;
	flag_test[1] = 0x40;
	r = lq_trust_check(pubkey_alice, store, TRUST_MATCH_ONE, (const unsigned char*)flag_test);
	ck_assert_int_eq(r, 1000000);

	store->free(store);
}
END_TEST

START_TEST(check_trust_best) {
	int r;
	unsigned char flag_test[2];
	LQPubKey *pubkey_alice;
	LQStore *store;
	char *lodata;
	size_t lolen;
	char path[1024];
	char *p;

	lq_cpy(path, "/tmp/lqstore_file_XXXXXX", 25);
	p = mktempdir(path);
	*(p+24) = '/';
	*(p+25) = 0x0;
	store = lq_store_new(p);
	ck_assert_ptr_nonnull(store->userdata);

	pubkey_alice = lq_publickey_new(pubkey_data_alice);

	lolen = lq_publickey_bytes(pubkey_alice, &lodata);
	store->put(LQ_CONTENT_KEY, store, lodata, &lolen, (char*)trust_alice, 2);

	flag_test[0] = 0x13;
	flag_test[1] = 0x60;
	r = lq_trust_check(pubkey_alice, store, TRUST_MATCH_BEST, (const unsigned char*)flag_test);
	ck_assert_int_eq(r, 600000);

	store->free(store);
}
END_TEST

START_TEST(check_trust_all) {
	int r;
	unsigned char flag_test[2];
	LQPubKey *pubkey_alice;
	LQStore *store;
	char *lodata;
	size_t lolen;
	char path[1024];
	char *p;

	lq_cpy(path, "/tmp/lqstore_file_XXXXXX", 25);
	p = mktempdir(path);
	*(p+24) = '/';
	*(p+25) = 0x0;
	store = lq_store_new(p);
	ck_assert_ptr_nonnull(store->userdata);

	pubkey_alice = lq_publickey_new(pubkey_data_alice);

	lolen = lq_publickey_bytes(pubkey_alice, &lodata);
	store->put(LQ_CONTENT_KEY, store, lodata, &lolen, (char*)trust_alice, 2);

	flag_test[0] = 0x13;
	flag_test[1] = 0x60;
	r = lq_trust_check(pubkey_alice, store, TRUST_MATCH_ALL, (const unsigned char*)flag_test);
	ck_assert_int_eq(r, 0);

	flag_test[0] = 0xff;
	flag_test[1] = 0xff;
	r = lq_trust_check(pubkey_alice, store, TRUST_MATCH_ALL, (const unsigned char*)flag_test);
	ck_assert_int_eq(r, 0);

	flag_test[0] = 0x01;
	flag_test[1] = 0x78;
	r = lq_trust_check(pubkey_alice, store, TRUST_MATCH_ALL, (const unsigned char*)flag_test);
	ck_assert_int_eq(r, 1000000);

	store->free(store);
}
END_TEST

Suite * common_suite(void) {
	Suite *s;
	TCase *tc;

	s = suite_create("trust");
	tc = tcase_create("check");
	tcase_add_test(tc, check_trust_none);
	tcase_add_test(tc, check_trust_one);
	tcase_add_test(tc, check_trust_best);
	tcase_add_test(tc, check_trust_all);
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
