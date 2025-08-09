#include <libtasn1.h>
#include <llog.h>
#include <stdlib.h>

//#include "tasn.h"
#include <lq/asn.h>
#include <lq/mem.h>
#include <lq/err.h>
#include "debug.h"


extern const asn1_static_node defs_asn1_tab[];
asn1_node asn;

// TODO: DRY
static int asn_except(asn1_node *node, int err) {
	int r;

	r = asn1_delete_structure(node);
	if (r != ASN1_SUCCESS) {
		debug_logerr(LLOG_ERROR, ERR_FAIL, "free asn");
	}

	return err;
}

static char* join_element(const char *domain, const char *element, char *s) {
	int r;
	char *p;

	p = s;
	r = lq_len(domain);
	lq_cpy(p, domain, r);
	p += r;
	s[r] = '.';
	p++;
	r = lq_len(element);
	lq_cpy(p, element, r);
	p += r;
	*p = 0x0;
	return s;
}

int lq_asn_init() {
	int r;

	r = asn1_array2tree(defs_asn1_tab, &asn, NULL);
	if (r != ASN1_SUCCESS) {
		return ERR_FAIL;
	}
	return ERR_OK;
}

LQASN* lq_asn_new(const char *element) {
	int r;
	LQASN *item;
	asn1_node o;

	lq_zero(&o, sizeof(o));
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
	char err[1024];
	char s[32];
	char *p;

	lq_zero(&o, sizeof(o));
	p = join_element("Qaeda", element, (char*)s);
	r = asn1_create_element(asn, p, &o);
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
	item->mode = LQASN_MODE_READ;
	o = (asn1_node)item->impl;

	r = asn1_der_decoding(&o, data, data_len, err);
	if (r != ASN1_SUCCESS) {
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
		return ERR_ENCODING;
	}

	return ERR_OK;
}

int lq_asn_write(LQASN *item, const char *property, const char *data, size_t data_len) {
	int r;
	int c;
	asn1_node o;
	char s[32];
	char *p;

	p = join_element(item->element, property, (char*)s);
	o = (asn1_node)item->impl;
	r = asn1_write_value(o, p, data, (int)data_len);
	if (r != ASN1_SUCCESS) {
		return ERR_ELEMENT_WRITE;
	}
	return ERR_OK;
}

int lq_asn_read(LQASN *item, const char *property, char *data, size_t *data_len) {
	int r;
	asn1_node o;

	o = (asn1_node)item->impl;
	r = asn1_read_value(o, property, data, (int*)data_len);
	if (r != ASN1_SUCCESS) {
		return ERR_ELEMENT_READ;
	}
	return ERR_OK;
}

void lq_asn_free(LQASN *item) {
	int r;
	asn1_node o;

	o = (asn1_node)item->impl;
	r = asn1_delete_structure(&o);
	if (r != ASN1_SUCCESS) {
		debug(LLOG_WARNING, item->element, "delete item");
	}
	lq_free(item);
}

void lq_asn_finish() {
}
