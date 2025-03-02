#include <stdlib.h>

char *mktempdir(char *s) {
	return mkdtemp(s);
}
