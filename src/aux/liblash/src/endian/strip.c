#include <stddef.h>

char* strip_be(char *value, size_t *len) {
	int i;
	char *p;
	
	p = value;
	for (i = 0; i < *len; i++) {
		if (*p & 0xff) {
			break;
		}
		p++;
	}
	*len -= i;
	if (!*len) {
		*len = 1;
		p--;
	}
	return p;
}

int strap_be(const char *in, size_t in_len, char *out, size_t out_len) {
	int i;
	int c;
	char *p;
	char mask;

	if (in_len > out_len) {
		return 1;
	}
	if (in_len == 0) {
		return 1;
	}

	mask = 0;
	if (*in & 0x80) {
		mask = 0xff;
	}
	for (i = 0; i < 4; i++) {
		*(out+i) = mask;
	}

	c = out_len - in_len;
	p = out + c;
	for (i = 0; i < in_len; i++) {
		*(p+i) = *(in+i);
	}

	return 0;
}
