/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <string.h>

#include "asinine/dsl.h"
#include "asinine/x509.h"
#include "internal/macros.h"

typedef struct {
	asn1_oid_t oid;
	x509_rdn_type_t type;
} rdn_type_lookup_t;

static const rdn_type_lookup_t rdn_types[] = {
    {ASN1_OID(1, 2, 840, 113549, 1, 9, 1), X509_RDN_EMAIL},
    {ASN1_OID(1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 3),
        X509_RDN_JURISDICTION_COUNTRY},
    {ASN1_OID(1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 2),
        X509_RDN_JURISDICTION_COUNTRY},
    {ASN1_OID(1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 1),
        X509_RDN_JURISDICTION_LOCALITY},
    {ASN1_OID(2, 5, 4, 3), X509_RDN_COMMON_NAME},
    {
        ASN1_OID(2, 5, 4, 4),
    },
    {ASN1_OID(2, 5, 4, 5), X509_RDN_SERIAL_NUMBER},
    {ASN1_OID(2, 5, 4, 6), X509_RDN_COUNTRY},
    {ASN1_OID(2, 5, 4, 7), X509_RDN_LOCALITY},
    {ASN1_OID(2, 5, 4, 8), X509_RDN_STATE_OR_PROVINCE},
    {ASN1_OID(2, 5, 4, 9), X509_RDN_STREET_ADDRESS},
    {ASN1_OID(2, 5, 4, 10), X509_RDN_ORGANIZATION},
    {ASN1_OID(2, 5, 4, 11), X509_RDN_ORGANIZATIONAL_UNIT},
    {ASN1_OID(2, 5, 4, 15), X509_RDN_BUSINESS_CATEGORY},
    {ASN1_OID(2, 5, 4, 17), X509_RDN_POSTAL_CODE},
    {ASN1_OID(2, 5, 4, 18), X509_RDN_PO_BOX},
    {ASN1_OID(2, 5, 4, 46), X509_RDN_DISTINGUISHED_NAME_QUALIFIER},
    {ASN1_OID(2, 5, 4, 49), X509_RDN_DISTINGUISHED_NAME},
    {ASN1_OID(2, 5, 4, 97), X509_RDN_ORGANIZATIONAL_ID},
};

/**
 * Parse an X.509 Name.
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
 * @return ASININE_OK on success, other error code otherwise.
 */
asinine_err_t
x509_parse_name(asn1_parser_t *parser, x509_name_t *name) {
	RETURN_ON_ERROR(x509_parse_optional_name(parser, name));
	if (name->num == 0) {
		return ERROR(ASININE_ERR_INVALID, "name: empty");
	}
	return ERROR(ASININE_OK, NULL);
}

static x509_rdn_type_t
find_rdn_type(const asn1_oid_t *oid) {
	for (size_t i = 0; i < NUM(rdn_types); i++) {
		if (asn1_oid_cmp(oid, &rdn_types[i].oid) == 0) {
			return rdn_types[i].type;
		}
	}
	return X509_RDN_INVALID;
}

/**
 * Parses an X.509 Name, which may be empty.
 */
asinine_err_t
x509_parse_optional_name(asn1_parser_t *parser, x509_name_t *name) {
	const asn1_token_t *token = &parser->token;

	*name = (x509_name_t){0};

	RETURN_ON_ERROR(asn1_push_seq(parser));

	// TODO: The sequence may be empty for V3 certificates, where the
	// subjectAltName extension is enabled.
	while (!asn1_eof(parser) && name->num < X509_MAX_RDNS) {
		// "RelativeDistinguishedName"
		NEXT_TOKEN(parser);

		if (!asn1_is_set(token)) {
			return ERROR(ASININE_ERR_INVALID, NULL);
		}

		RETURN_ON_ERROR(asn1_push(parser));

		// "AttributeValueAssertion"
		RETURN_ON_ERROR(asn1_push_seq(parser));

		// Get identifiying key (OID)
		NEXT_TOKEN(parser);

		if (!asn1_is_oid(token)) {
			return ERROR(ASININE_ERR_INVALID, NULL);
		}

		asn1_oid_t oid;
		RETURN_ON_ERROR(asn1_oid(token, &oid));

		x509_rdn_type_t type = find_rdn_type(&oid);
		if (type == X509_RDN_INVALID) {
			return ERROR(ASININE_ERR_UNSUPPORTED, "name: unknown RDN");
		}

		// Get string value
		NEXT_TOKEN(parser);
		if (!asn1_is_string(token)) {
			return ERROR(ASININE_ERR_INVALID, NULL);
		}

		name->rdns[name->num].type  = type;
		name->rdns[name->num].value = *token;
		name->num++;

		// End of AVA
		RETURN_ON_ERROR(asn1_pop(parser));

		// TODO: Currently, only one AVA per RDN is supported
		if (!asn1_eof(parser)) {
			return ERROR(ASININE_ERR_UNSUPPORTED, "name: multiple AVA");
		}

		// End of RDN
		RETURN_ON_ERROR(asn1_pop(parser));
	}

	if (!asn1_eof(parser)) {
		return ERROR(ASININE_ERR_MEMORY, "name: too many RDNs");
	}

	x509_sort_name(name);

	return asn1_pop(parser);
}

void
x509_sort_name(x509_name_t *name) {
	for (size_t i = 1; i < name->num; i++) {
		x509_rdn_t temp = name->rdns[i];
		size_t j        = i;
		while (j > 0 && name->rdns[j - 1].type > temp.type) {
			name->rdns[j] = name->rdns[j - 1];
			j--;
		}
		name->rdns[j] = temp;
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

		if (a_rdn->type != b_rdn->type) {
			set_reason(reason, "attribute type mismatch");
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

asinine_err_t
x509_parse_alt_names(asn1_parser_t *parser, x509_alt_names_t *alt_names) {
	const asn1_token_t *token = &parser->token;

	*alt_names = (x509_alt_names_t){0};

	RETURN_ON_ERROR(asn1_push_seq(parser));

	// Alternative names must contain at least one name
	size_t i = 0;
	do {
		NEXT_TOKEN(parser);

		asn1_type_t type = token->type;
		if (type.class != ASN1_CLASS_CONTEXT) {
			return ERROR(ASININE_ERR_INVALID, NULL);
		}

		switch ((uint8_t)type.tag) {
		case X509_ALT_NAME_RFC822NAME:
			if (token->length == 0) {
				return ERROR(ASININE_ERR_INVALID, "SAN: empty RFC822Name");
			}
			break;
		case X509_ALT_NAME_DNSNAME:
			if (token->length == 0) {
				return ERROR(ASININE_ERR_INVALID, "SAN: empty DNSName");
			}
			if (token->length == 1 && token->data[0] == ' ') {
				return ERROR(ASININE_ERR_INVALID, "SAN: empty DNSName");
			}
			break;
		case X509_ALT_NAME_URI:
			if (token->length == 0) {
				return ERROR(ASININE_ERR_INVALID, "SAN: empty URI");
			}
			// TODO: "The name
			//    MUST NOT be a relative URI, and it MUST follow the URI syntax
			//    and encoding rules specified in [RFC3986].  The name MUST
			//    include both a scheme (e.g., "http" or "ftp") and a
			//    scheme-specific-part.  URIs that include an authority
			//    ([RFC3986], Section 3.2) MUST include a fully qualified domain
			//    name or IP address as the host.
			//    As specified in [RFC3986], the scheme name is not
			//    case-sensitive (e.g., "http" is equivalent to "HTTP").  The
			//    host part, if present, is also not case-sensitive, but other
			//    components of the scheme-specific-part may be
			//    case-sensitive."
			break;
		case X509_ALT_NAME_IP:
			if (token->length != 4 && token->length != 16) {
				return ERROR(ASININE_ERR_INVALID, "SAN: invalid IP");
			}
			break;
		case X509_ALT_NAME_DIRECTORY: // directoryName
			if (type.encoding != ASN1_ENCODING_CONSTRUCTED) {
				return ERROR(ASININE_ERR_INVALID, NULL);
			}

			if (alt_names->directory_num + 1 > NUM(alt_names->directory)) {
				return ERROR(
				    ASININE_ERR_MEMORY, "SAN: too many directoryNames");
			}

			RETURN_ON_ERROR(asn1_push(parser));

			RETURN_ON_ERROR(x509_parse_name(
			    parser, &alt_names->directory[alt_names->directory_num]));
			alt_names->directory_num++;

			RETURN_ON_ERROR(asn1_pop(parser));

			// Skip regular SAN decode
			continue;
		case 0: // otherName
		case 3: // x400Address
		case 5: // ediPartyName
		case 8: // registeredID
			return ERROR(ASININE_ERR_UNSUPPORTED, "name: unknown SAN");
		default:
			return ERROR(ASININE_ERR_INVALID, "name: unknown SAN");
		}

		// At least directoryName uses constructed encoding, so we check
		// here to return UNSUPPORTED instead of INVALID.
		if (type.encoding != ASN1_ENCODING_PRIMITIVE) {
			return ERROR(ASININE_ERR_INVALID, NULL);
		}

		alt_names->names[i].type   = (x509_alt_name_type_t)type.tag;
		alt_names->names[i].data   = token->data;
		alt_names->names[i].length = token->length;
		alt_names->num             = ++i;
	} while (!asn1_eof(parser) && i < X509_MAX_ALT_NAMES);

	if (!asn1_eof(parser)) {
		return ERROR(ASININE_ERR_MEMORY, "name: too many SANs");
	}

	return asn1_pop(parser);
}

const char *
x509_rdn_type_string(x509_rdn_type_t type) {
	switch (type) {
	case X509_RDN_INVALID:
		return "INVALID";
	case X509_RDN_COUNTRY:
		return "Country";
	case X509_RDN_STATE_OR_PROVINCE:
		return "State or Province";
	case X509_RDN_LOCALITY:
		return "Locality";
	case X509_RDN_ORGANIZATION:
		return "Organization";
	case X509_RDN_ORGANIZATIONAL_UNIT:
		return "Organizational Unit";
	case X509_RDN_ORGANIZATIONAL_ID:
		return "Organizational ID";
	case X509_RDN_DISTINGUISHED_NAME:
		return "Distinguished Name";
	case X509_RDN_DISTINGUISHED_NAME_QUALIFIER:
		return "Distinguished Name Qualifier";
	case X509_RDN_COMMON_NAME:
		return "Common Name";
	case X509_RDN_SERIAL_NUMBER:
		return "Serial Number";
	case X509_RDN_EMAIL:
		return "E-Mail";
	case X509_RDN_BUSINESS_CATEGORY:
		return "Business category";
	case X509_RDN_JURISDICTION_COUNTRY:
		return "Jurisdiction (Country)";
	case X509_RDN_JURISDICTION_STATE_OR_PROVINCE:
		return "Jurisdiction (State or Province)";
	case X509_RDN_JURISDICTION_LOCALITY:
		return "Jurisdiction (Locality)";
	case X509_RDN_POSTAL_CODE:
		return "Postal code";
	case X509_RDN_PO_BOX:
		return "PO Box";
	case X509_RDN_STREET_ADDRESS:
		return "Street address";
	case X509_RDN_SURNAME:
		return "Surname";
	}
	return "(INVALID)";
}
