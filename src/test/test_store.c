#include <check.h>
#include <stdlib.h>
#include <string.h>

#include "lq/store.h"
#include "lq/mem.h"
#include "lq/io.h"


extern LQStore LQFileContent;

START_TEST(check_store_count) {
	int r;
	LQStore store;
	char *k;
	char *v;
	size_t kl;
	size_t vl;
	char path[LQ_PATH_MAX];

	lq_cpy(&store, &LQFileContent, sizeof(LQStore));
	lq_cpy(path, "/tmp/lqstore_file_XXXXXX", 25);
	store.userdata = mktempdir(path);
	*((char*)(store.userdata+24)) = '/';
	*((char*)(store.userdata+25)) = 0x0;
	
	k = "aaa";
	v = "foo";
	kl = 3;
	vl = 3;
	store.put(LQ_CONTENT_RAW, &store, k, &kl, v, vl), 

	k = "ab";
	v = "bar";
	kl = 2;
	vl = 3;
	store.put(LQ_CONTENT_RAW, &store, k, &kl, v, vl), 

	k = "aaa";
	v = "inky";
	kl = 3;
	vl = 4;
	store.put(LQ_CONTENT_MSG, &store, k, &kl, v, vl), 

	k = "aab";
	v = "pinky";
	kl = 3;
	vl = 5;
	store.put(LQ_CONTENT_MSG, &store, k, &kl, v, vl), 

	k = "b";
	v = "blinky";
	kl = 1;
	vl = 6;
	store.put(LQ_CONTENT_MSG, &store, k, &kl, v, vl), 

	k = "bbc";
	v = "clyde";
	kl = 3;
	vl = 5;
	store.put(LQ_CONTENT_MSG, &store, k, &kl, v, vl), 

	k = "bbc";
	v = "clyde";
	kl = 3;
	vl = 5;
	store.put(LQ_CONTENT_CERT, &store, k, &kl, v, vl), 

	r = store.count(LQ_CONTENT_MSG, &store, "aa", 2);

	ck_assert_int_eq(r, 2);
}
END_TEST

Suite * common_suite(void) {
	Suite *s;
	TCase *tc;

	s = suite_create("store");
	tc = tcase_create("files");
	tcase_add_test(tc, check_store_count);
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
