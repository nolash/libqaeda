#include <string.h>

#include "rerr.h"

char *bars[3] = {
	"inky",
	"pinky",
	"blinky",
};

int main() {
	const char *s;
	char v[1024];
	rerr_init("core");

	s = rerrpfx(0);
	if (strcmp(s, "core")) {
		return 1;
	}

	s = rerrstr(0, v);
	if (strcmp(s, "core: OK")) {
		return 1;
	}

	rerr_register(0x200, "bar", bars);

	s = rerrstr(0x202, v);
	if (strcmp(s, "bar: blinky")) {
		return 1;
	}

	s = rerrstrv(0x202);
	if (strcmp(s, "blinky")) {
		return 1;
	}

	s = rerrpfx(0x202);
	if (strcmp(s, "bar")) {
		return 1;
	}

	return 0;
}
