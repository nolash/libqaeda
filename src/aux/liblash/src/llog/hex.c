#include <stdio.h>

char *_x = "0123456789abcdef";

void b2h(const unsigned char *data, int l, unsigned char *zHex) {
        unsigned int i;

        for (i = 0; i < l; i++) {
                sprintf((char*)zHex+(i*2), "%02x", *(data+i));
        }
}

char* c2h(char in, char *out) {
	char i;
	i = in & 0x0f;
	*(out+1) = *(_x+i);
	in >>= 4;
	i = in & 0x0f;
	*out = *(_x+i);
	return out;
}
