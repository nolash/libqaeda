#include <string.h>
#include <stddef.h>
#include <stdio.h>

#include "strip.h"
#include "endian.h"

static int test_strip() {
	size_t l = 4;
	char be_int_semi[4] = {0x00, 0x00, 0x02, 0x9f};
	char be_int_full[4] = {0x40, 0x00, 0x02, 0x9f};
	char be_int_zero[4] = {0x00, 0x00, 0x00, 0x00};
	char be_int_mini[1] = {0x2a};
	char be_int_mini_zero[1] = {0x00};
	char *r;
	
	r = strip_be((char*)be_int_semi, &l);
	if (l != 2) {
		return 1;
	}
	if (*r != 0x02) {
		return 1;
	}

	l = 4;
	r = strip_be((char*)be_int_full, &l);
	if (l != 4) {
		return 1;
	}
	if (*r != 0x40) {
		return 1;
	}

	l = 4;
	r = strip_be((char*)be_int_zero, &l);
	if (l != 1) {
		return 1;
	}
	if (*r != 0x00) {
		return 1;
	}

	l = 1;
	r = strip_be((char*)be_int_mini, &l);
	if (l != 1) {
		return 1;
	}
	if (*r != 0x2a) {
		return 1;
	}

	l = 1;
	r = strip_be((char*)be_int_mini_zero, &l);
	if (l != 1) {
		return 1;
	}
	if (*r != 0x00) {
		return 1;
	}

	return 0;
}

static int test_strap() {
	int r;
	char v_neg[] = {0xfe, 0xf2, 0x00, 0x00};
	char v_pos[] = {0x02, 0x9a, 0x00, 0x00};
	char v_full[] = {0x2a, 0x13, 0x24, 0x35};
	char v_full_neg[] = {0xfa, 0x13, 0x24, 0x35};
	char out[4];
	int *p;

	memset(out, 0, 4);
	r = strap_be(v_neg, 2, out, 4);
	if (r) {
		return r;
	}
	if (is_le()) {
		flip_endian(4, out);
	}
	p = (int*)out;
	if (*p != -270) {
		return 1;
	}

	memset(out, 0, 4);
	r = strap_be(v_pos, 2, out, 4);
	if (r) {
		return r;
	}
	if (is_le()) {
		flip_endian(4, out);
	}
	p = (int*)out;
	if (*p != 666) {
		return 1;
	}

	memset(out, 0, 4);
	r = strap_be(v_full, 1, out, 4);
	if (r) {
		return r;
	}
	if (is_le()) {
		flip_endian(4, out);
	}
	p = (int*)out;
	if (*p != 42) {
		return 1;
	}

	memset(out, 0, 4);
	r = strap_be(v_full, 3, out, 4);
	if (r) {
		return r;
	}
	if (is_le()) {
		flip_endian(4, out);
	}
	p = (int*)out;
	if (*p != 2757412) {
		return 1;
	}

	memset(out, 0, 4);
	r = strap_be(v_full, 4, out, 4);
	if (r) {
		return r;
	}
	if (is_le()) {
		flip_endian(4, out);
	}
	p = (int*)out;
	if (*p != 705897525) {
		return 1;
	}

	memset(out, 0, 4);
	r = strap_be(v_full_neg, 4, out, 4);
	if (r) {
		return r;
	}
	if (is_le()) {
		flip_endian(4, out);
	}
	p = (int*)out;
	if (*p != -99408843) {
		return 1;
	}

	return 0;
}

int main() {
	int r;

	r = test_strip();
	if (r) {
		return r;
	}

	r = test_strap();
	if (r) {
		return r;
	}

	return 0;
}
