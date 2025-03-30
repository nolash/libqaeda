#include <check.h>
#include <stdlib.h>
#include <string.h>

#include "lq/msg.h"
#include "lq/crypto.h"
#include "lq/io.h"
#include "lq/mem.h"

extern LQStore LQDummyContent;
extern LQStore LQFileContent;

const char *data = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";

START_TEST(check_msg_symmetric) {
	int r;
	size_t c;
	char buf[4096];
	char path[1024];
	char *p;
	LQMsg *msg;
	LQResolve resolve;
	LQResolve resolve_dummy;
	LQStore *store;

	lq_cpy(path, "/tmp/lqstore_file_XXXXXX", 25);
	p = mktempdir(path);
	*(p+24) = '/';
	*(p+25) = 0x0;
	store = lq_store_new(p);
	ck_assert_ptr_nonnull(store->userdata);

	resolve_dummy.store = &LQDummyContent;
	resolve_dummy.next = NULL;
	resolve.store = store;
	resolve.next = &resolve_dummy;
	msg = lq_msg_new(data, strlen(data) + 1);
	msg->pubkey = lq_publickey_new(data);

	c = 4096;
	r = lq_msg_serialize(msg, buf, &c, &resolve);
	ck_assert_int_eq(r, 0);
	lq_msg_free(msg);

	r = lq_msg_deserialize(&msg, buf, c, &resolve);
	ck_assert_ptr_nonnull(msg);
	ck_assert_int_eq(r, 0);
	lq_msg_free(msg);
	resolve.store->free(resolve.store);
	resolve_dummy.store->free(resolve_dummy.store);
}
END_TEST

Suite * common_suite(void) {
	Suite *s;
	TCase *tc;

	s = suite_create("msg");
	tc = tcase_create("serialize");
	tcase_add_test(tc, check_msg_symmetric);
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
