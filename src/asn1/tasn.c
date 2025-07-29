#include <libtasn1.h>
#include <llog.h>

#include <lq/asn.h>
#include <lq/err.h>
#include "debug.h"

extern asn1_node asn;


LQASN* lq_asn_new(const char *element) {
	int r;
	LQASN *item;
	asn1_node o;

	r = asn1_create_element(asn, "Qaeda", &o);
	if (r != ASN1_SUCCESS) {
		return NULL;
	}
	item = lq_alloc(sizeof(LQASN));
	if (item == NULL) {
		return NULL;
	}
	lq_zero(item, sizeof(LQASN));

	lq_cpy(item->element, element, lq_len(element));
	item->impl = (void*)o;

	return item;
}

LQASN* lq_asn_parse(const char *element, const char *data, size_t data_len) {
	int r;
	LQASN *item;
	asn1_node o;

	item = lq_asn_new(element);
	item->mode = LQASN_MODE_READ;
	o = (asn1_node)item->impl;

	r = asn1_der_decoding(&o, in, in_len, err);
	if (r != ASN1_SUCCESS) {
		//return asn_except(&item, ERR_ENCODING);
		return NULL;
	}
	return item;
}

int lq_asn_out(LQASN *item, char *out, size_t *out_len) {
	int r;
	char err[1024];
	asn1_node o;

	o = (asn1_node)item->impl;
	r = asn1_der_coding(o, item->element, out, (int*)out_len, err);
	if (r != ASN1_SUCCESS) {
		debug_logerr(LLOG_WARNING, ERR_ENCODING, (char*)asn1_strerror(r));
		//return asn_except(&item, ERR_ENCODING);
		return ERR_ENCODING;
	}

	return ERR_OK;
}

int lq_asn_write(LQASN *item, const char *property, const *data, size_t data_len) {
	int r;
	int c;
	asn1_node o;
	char s[32];
	char p;

	p = (char*)s;
	r = lq_len(item->element);
	lq_cpy(p, item->element, r);
	p += r;
	s[r] = ".";
	p++;
	r = lq_len(property);
	lq_cpy(p, property, r);
	p++;
	*p = 0x0;

	o = (asn1_node)item->impl;
	r = asn1_write_value(o, p, data, (int)data_len);
	if (r != ASN1_SUCCESS) {
		return ERR_ELEMENT_WRITE;
	}
	return ERR_OK;
}

int lq_asn_read(LQASN *item, const char *property, const *data, size_t *data_len) {
	int r;
	asn1_node o;

	o = (asn1_node)item->impl;
	r = asn1_read_value(o, property, data, (int*)data_len);
	if (r != ASN1_SUCCESS) {
		return ERR_ELEMENT_READ;
		//return asn_except(&item, ERR_READ);
	}
	return ERR_OK;
}

void lq_asn_free(LQASN *item) {
	asn1_node o;

	o = (asn1_node)item->impl;
	r = asn1_delete_structure(&o);
	if (r != ASN1_SUCCESS) {
		debug(LLOG_WARNING, item->element, "delete item");
	}
	free(item);
}
