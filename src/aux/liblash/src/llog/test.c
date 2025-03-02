#include <stdio.h>
#include <string.h>

#include "llog.h"

void llog_out(const char *v) {
	fprintf(stderr, "%s\n", v);
}

int main() {
	char *p;
	char beef[] = { 0xbe, 0xef };

	p = llog_new(LLOG_CRITICAL, "foo");
	if (strcmp("[crt] foo", p)) {
		return 1;
	}
	llog_out(p);

	p = llog_add_s("bar", "baz");
	if (strcmp("[crt] foo\tbar=baz", p)) {
		return 1;
	}

	p = llog_add_n("xyzzy", 42);
	if (strcmp("[crt] foo\tbar=baz\txyzzy=42", p)) {
		return 1;
	}

	p = llog_add_b("dead", (void*)beef, 2);
	if (strcmp("[crt] foo\tbar=baz\txyzzy=42\tdead=beef", p)) {
		return 1;
	}

	p = llog_new_ns(LLOG_CRITICAL, "pinky", "inky");
	if (strcmp("[inky][crt] pinky", p)) {
		return 1;
	}

	p = llog_add_s("blinky", "clyde");
	if (strcmp("[inky][crt] pinky\tblinky=clyde", p)) {
		return 1;
	}

	p = llog_new(LLOG_INFO, "foo");
	p = llog_add_x("bar", 666);
	if (strcmp("[inf] foo\tbar=0x029a", p)) {
		return 1;
	}


	return 0;
}
