void uc(char *b) {
	int i;
	char v;

	i = 0;
	v = 1;
	while(v > 0) {
		v = *(b+i);
		if (v > 0x60 && v < 0x7b) {
			*(b+i) -= 0x20;
		}
		i++;
	}
}

void lc(char *b) {
	int i;
	char v;

	i = 0;
	v = 1;
	while(v > 0) {
		v = *(b+i);
		if (v > 0x40 && v < 0x5b) {
			*(b+i) += 0x20;
		}
		i++;
	}
}
