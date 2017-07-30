/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <string.h>

#include "asinine/dsl.h"
#include "asinine/x509.h"

/**
* Parse a X.509 Name.
*
* A Name is structured as follows:
*
*   SEQUENCE OF
*     SET OF (one or more) (V3 with subjectAltName: zero) (= RDN)
*       SEQUENCE (= AVA)
*         OID Type
*         ANY Value
*
* @param  parser Current position in the ASN.1 structure
* @param  name Name structure to parse into
* @return ASININE_OK on success, other err
or code otherwise.
*/
asinine_err_t
x509_parse_name(asn1_parser_t *parser, x509_name_t *name) {
	const asn1_token_t *token = &parser->token;

	*name = (x509_name_t){0};

	RETURN_ON_ERROR(asn1_push_seq(parser));

	// TODO: The sequence may be empty for V3 certificates, where the
	// subjectAltName extension is enabled.
	while (!asn1_eof(parser) && name->num < X509_MAX_RDNS) {
		// "RelativeDistinguishedName"
		NEXT_TOKEN(parser);

		if (!asn1_is_set(token)) {
			return ASININE_ERROR_INVALID;
		}

		RETURN_ON_ERROR(asn1_push(parser));

		// "AttributeValueAssertion"
		RETURN_ON_ERROR(asn1_push_seq(parser));

		// Get identifiying key (OID)
		NEXT_TOKEN(parser);

		if (!asn1_is_oid(token)) {
			return ASININE_ERROR_INVALID;
		}

		if (asn1_oid(token, &(name->rdns[name->num].oid)) < ASININE_OK) {
			return ASININE_ERROR_INVALID;
		}

		// Get string value
		NEXT_TOKEN(parser);
		if (!asn1_is_string(token)) {
			return ASININE_ERROR_INVALID;
		}

		name->rdns[name->num].value = *token;
		name->num++;

		// End of AVA
		RETURN_ON_ERROR(asn1_pop(parser));

		// TODO: Currently, only one AVA per RDN is supported
		if (!asn1_eof(parser)) {
			return ASININE_ERROR_UNSUPPORTED;
		}

		// End of RDN
		RETURN_ON_ERROR(asn1_pop(parser));
	}

	if (!asn1_eof(parser)) {
		return ASININE_ERROR_MEMORY;
	}

	x509_sort_name(name);

	return asn1_pop(parser);
}

void
x509_sort_name(x509_name_t *name) {
	for (size_t i = 1; i < name->num; i++) {
		x509_rdn_t temp = name->rdns[i];
		size_t j        = i - 1;

		while (j > 0 && asn1_oid_cmp(&name->rdns[j].oid, &temp.oid) > 0) {
			name->rdns[j + 1] = name->rdns[j];
			j--;
		}

		name->rdns[j + 1] = temp;
	}
}

static void
set_reason(const char **ptr, const char *reason) {
	if (ptr == NULL) {
		return;
	}
	*ptr = reason;
}

bool
x509_name_eq(const x509_name_t *a, const x509_name_t *b, const char **reason) {
	if (a->num != b->num) {
		set_reason(reason, "differing number of RDNs");
		return false;
	}

	for (size_t i = 0; i < a->num; i++) {
		const x509_rdn_t *a_rdn = &a->rdns[i];
		const x509_rdn_t *b_rdn = &b->rdns[i];

		if (asn1_oid_cmp(&a_rdn->oid, &b_rdn->oid) != 0) {
			set_reason(reason, "attribute mismatch");
			return false;
		}

		if (a_rdn->value.length != b_rdn->value.length) {
			set_reason(reason, "value length mismatch");
			return false;
		}

		// TODO: This should compare normalised strings:
		//  - ignore case
		//  - decode from various charsets into a canonical one
		if (memcmp(a_rdn->value.data, b_rdn->value.data, a_rdn->value.length) !=
		    0) {
			set_reason(reason, "value mismatch");
			return false;
		}
	}

	set_reason(reason, NULL);
	return true;
}
