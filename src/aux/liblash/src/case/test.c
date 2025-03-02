#include <string.h>

#include "case.h"


int test_uc() {
	char data[] = "fO13_oBar";
	
	uc(data);
	if (strcmp(data, "FO13_OBAR")) {
		return 1;
	}
	return 0;
}

int test_lc() {
	char data[] = "FooB12_aR";
	
	lc(data);
	if (strcmp(data, "foob12_ar")) {
		return 1;
	}
	return 0;
}

int main() {
	int r;

	r = test_uc();
	if (r) {
		return 1;
	}

	r = test_lc();
	if (r) {
		return 2;
	}

	return 0;
}
