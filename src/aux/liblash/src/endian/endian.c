#include "endian.h"

int is_le() {
	unsigned short s = 42;
	return *((unsigned char*)&s) == 42;
}


void flip_endian(int l, void *v) {
	int i;
	char t;
	char *ne;
	char *p;

	p = (char*)v;
	ne = p+(l-1);
	for (i = 0; i < l/2; i++) {
		t = *(p+i);
		*(p+i) = *(ne-i);
		*(ne-i) = t;
	}
}

int to_endian(char direction, int l, void *n) {
	union le un;

	if (l == 1 || is_le() == direction) {
		return 0;
	}
	switch(l) {
		case sizeof(long long):
			un.ll = (long long*)n;	
			break;
		case sizeof(int):
			un.i = (int*)n;	
			break;
		case sizeof(short):
			un.s = (short*)n;	
			break;
		default:
			return 1;
	}
	flip_endian(l, un.c);

	return 0;
}

