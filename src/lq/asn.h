#ifndef LIBQAEDA_ASN_H_
#define LIBQAEDA_ASN_H_

#define ASN_DOMAIN "Qaeda"
#define LQASN_MODE_WRITE 0
#define LQASN_MODE_READ 1

struct LQASN {
	const char element[32];
	void *impl;
	int mode;
};

LQASN* lq_asn_new(const char *element);
LQASN* lq_asn_parse(const char *element, const char *data, size_t data_len);
int lq_asn_write(LQASN *asn, const char *property, const *data, size_t data_len);
int lq_asn_out(LQASN *asn, char *out, size_t *out_len);
int lq_asn_read(LQASN *asn, const char *property, const *data, size_t data_len);
void lq_asn_free(LQASN*);

#endif // LIBQAEDA_ASN_H_
