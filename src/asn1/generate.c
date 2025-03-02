#include <string.h>
#include <stdio.h>
#include <libtasn1.h>

int main() {
	int r;
	char err[1024];
	asn1_node node;

	err[0] = 0;
	memset(&node, 0, sizeof(asn1_node));

	r = asn1_parser2array("./defs.txt", NULL, NULL, err);
	if (r) {
		fprintf(stderr, "%s\n", err);
		return r;
	}
	return 0;

}
