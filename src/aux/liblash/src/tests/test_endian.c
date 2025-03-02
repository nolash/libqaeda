#include <string.h>
#include <stdio.h>

#include "endian.h"
#include "strip.h"


int main() {
	int r;
	int i;
	char left[] = { 0x02, 0x13, 0x24, 0x35};
	char right[] = { 0x35, 0x24, 0x13, 0x02};
	unsigned char tmp[4];

	memcpy(tmp, left, 4);

	// four byte flip
	flip_endian(4, tmp);
	for (i = 0; i < 4; i++) {
		if (tmp[i] != *(right+i)) {
			return 1;
		}
	}

	// two byte flip
	memcpy(tmp, left, 2);
	flip_endian(2, tmp);
	for (i = 0; i < 4; i++) {
		if (tmp[i] != *(right+2+i)) {
			return 1;
		}
	}

	// single byte flip
	tmp[0] = 0x2a;
	flip_endian(1, tmp);
	tmp[0] = 0x2a;


	// check explicit endian convert
	if (is_le()) {
		memcpy(tmp, left, 4);
	} else {
		memcpy(tmp, right, 4);
	}
	r = to_endian(0, 4, (void*)tmp);
	if (r) {
		return 1;
	}
	for (i = 0; i < 4; i++) {
		if (tmp[i] != *(right+i)) {
			return 1;
		}
	}

	// check invalid length
	r = to_endian(0, 3, (void*)tmp);
	if (!r) {
		return 1;
	}

	return 0;
}
