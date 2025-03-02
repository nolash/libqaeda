#include <string.h>

#include "hex.h"

char test_bin[] = {0xde, 0xad, 0xbe, 0xef};
char test_hex[] = "deadbeef";
char *test_empty = "";

int test_from_string() {
	int i;
	char v[4];
	int r;

	r = h2b(test_hex, v);
	if (r != 4) {
		return 1;
	}
	for (i = 0; i < 4; i++) {
		if (test_bin[i] != v[i]) {
			return 1;
		}
	}
	return 0;
}

int test_from_bin() {
	int r;
	char v[9];

	b2h(test_bin, 4, v);
	if (strcmp(v, test_hex)) {
		return 1;
	}
	return 0;
}


int main() {
	int r;

	r = test_from_string();
	if (r) {
		return 1;
	}

	r = test_from_bin();
	if (r) {
		return 1;
	}
	

	return 0;
}
