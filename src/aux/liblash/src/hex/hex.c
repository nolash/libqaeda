char *_x = "0123456789abcdef";

void b2c(char in, char *out) {
	int v;

	v = (in & 0xf0) >> 4;
	*out = *(_x+v);
	v = in & 0x0f;
	*(out+1) = *(_x+v);
}

void b2h(const unsigned char *in, int l, unsigned char *out) {
        int i;
	char *p;

	p = (char*)out;
        for (i = 0; i < l; i++) {
		b2c(*(in+i), p);
		p += 2;
	}
	*p = 0;
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

int n2b(const char in, char *out) {
	if (out == 0x0) {
		return 1;
	}

	if (in >= '0' && in <= '9') {
		*out = in - '0';
	} else if (in >= 'A' && in <= 'F') {
		*out = in - 'A' + 10;
	} else if (in >= 'a' && in <= 'f') {
		*out = in - 'a' + 10;
	} else {
		return 1;
	}

	return 0;
}

int h2b(const char *in, unsigned char *out) {
	int r;
	int i;
	char b1;
	char b2;
	char *po;
	char *pi;

	if (in == 0x0 || *in == '\0' || out == 0x0) {
		return 0;
	}

	i = 0;
	po = (char*)out;
	pi = (char*)in;
	while (1) {
		if (*pi == 0) {
			break;
		}
		r = n2b(*pi, &b1);
		if (r) {
			return 0;
		}
		pi++;
		if (*pi == 0) { // we dont allow cut strings
			return 0;
		}
		r = n2b(*pi, &b2);
		if (r) {
			return 0;
		}
		pi++;

		//(*out)[i] = (b1 << 4) | b2;
		*po = (b1 << 4) | b2;
		po++;
		i++;
	}
	return i;

}
