#include <check.h>
#include <stdlib.h>

#include "lq/base.h"
#include "lq/io.h"
#include "lq/mem.h"
#include "lq/store.h"

// sha256sum "foo" 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
static const char foosum[32] = {
	0x2c, 0x26, 0xb4, 0x6b, 0x68, 0xff, 0xc6, 0x8f,
	0xf9, 0x9b, 0x45, 0x3c, 0x1d, 0x30, 0x41, 0x34,
	0x13, 0x42, 0x2d, 0x70, 0x64, 0x83, 0xbf, 0xa0,
	0xf9, 0x8a, 0x5e, 0x88, 0x62, 0x66, 0xe7, 0xae,
};


START_TEST(check_hashmap) {
	LQStore *store;
	char path[LQ_PATH_MAX];
	const char *k;
	size_t kl;
	char *v;
	size_t vl;
	int i;
	char out[8192];
	char in[8192];

	lq_cpy(path, "/tmp/lq_test_XXXXXX", 20);
	store = lq_store_new(mktempdir(path));
	ck_assert_ptr_nonnull(store);

	k = "foo";
	kl = 3;
	v = "bar";
	vl = 3;
	store->put(LQ_CONTENT_RAW, store, k, &kl, v, vl);

	v = out;
	vl = 8192;
	store->get(LQ_CONTENT_RAW, store, k, kl, v, &vl);

	k = foosum;
	kl = 32;
	for (i = 0; i < 8192; i++) {
		in[i] = i % 256;
	}
	v = in;
	vl = 8192;
	store->put(LQ_CONTENT_KEY, store, k, &kl, v, vl);

	v = out;
	store->get(LQ_CONTENT_KEY, store, k, kl, v, &vl);

	ck_assert_mem_eq(in, out, 8192);

	store->free(store);
}
END_TEST


Suite * common_suite(void) {
	Suite *s;
	TCase *tc;

	s = suite_create("test");
	tc = tcase_create("provisions");
	tcase_add_test(tc, check_hashmap);
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
