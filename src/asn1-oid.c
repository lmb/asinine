/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "asinine/asn1.h"

#define MIN(a,b) (((a) < (b)) ? a : b)

#define OID_MINIMUM_ARCS 2

#define OID_CONTINUATION_MASK (1<<7)
#define OID_VALUE_MASK ((1<<7)-1)
#define OID_VALUE_BITS_PER_BYTE 7

static int
append_arc(asn1_oid_t *oid, asn1_oid_arc_t arc)
{
	if (oid->num >= ASN1_OID_MAXIMUM_DEPTH) {
		return 0;
	}

	oid->arcs[oid->num++] = arc;
	return 1;
}

// 8.19
asn1_err_t
asn1_oid(const asn1_token_t *token, asn1_oid_t *oid)
{
	asn1_oid_arc_t arc;
	bool is_first_arc;
	size_t arc_bits;
	const uint8_t *data;

	memset(oid, 0, sizeof(*oid));

	if (!asn1_is(token, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_OID)) {
		return ASN1_ERROR_INVALID;
	}

	if (token->data == NULL || token->length == 0) {
		return ASN1_ERROR_INVALID;
	}

	// 8.19.2 "[...] last in the series: bit 8 of the last octet is zero; [...]"
	// Since we need to have the end of a series at the end of this token, we
	// check here.
	if ((*(token->data + token->length - 1) & OID_CONTINUATION_MASK) != 0) {
		return ASN1_ERROR_INVALID;
	}

	arc = 0;
	arc_bits = 0;
	is_first_arc = 1;

	for (data = token->data; data < token->data + token->length; data++) {
		if (arc == 0 && *data == 0x80) {
			// 8.19.2 "the leading octet of the subidentifier shall not have the
			// value 0x80"
			return ASN1_ERROR_INVALID;
		} 

		arc = (arc << OID_VALUE_BITS_PER_BYTE) | (*data & OID_VALUE_MASK);
		arc_bits += OID_VALUE_BITS_PER_BYTE;

		if (arc_bits > sizeof(arc) * 8) {
			return ASN1_ERROR_MEMORY;
		}

		if ((*data & OID_CONTINUATION_MASK) == 0) {
			if (is_first_arc) {
				// 8.19.4 + .5
				// If first arc is 2, values > 39 can be encoded for the second
				// one.
				asn1_oid_arc_t x = MIN(arc, 80) / 40;

				if (!append_arc(oid, x)) {
					return ASN1_ERROR_MEMORY;
				}

				arc = (arc - (x * 40));
				is_first_arc = 0;
			}

			if (!append_arc(oid, arc)) {
				return ASN1_ERROR_MEMORY;
			}

			arc = 0;
			arc_bits = 0;
		}
	}

	return ASN1_OK;
}

bool
asn1_oid_to_string(const asn1_oid_t *oid, char *buffer, size_t num)
{
	size_t i, total_written = 0;

	if (oid->num < OID_MINIMUM_ARCS) {
		return false;
	}

	for (i = 0; i < oid->num; i++) {
		size_t written;

		if (num == 0) {
			return ASN1_ERROR_MEMORY;
		}

		written = snprintf(buffer, num, "%d.", oid->arcs[i]);

		buffer += written;
		num -= written;
		total_written += written;
	}

	if (total_written && *(buffer-1) == '.') {
		*(buffer-1) = '\0';
	}

	return true;
}

int
asn1_oid_eq(const asn1_oid_t *oid, size_t num, ...)
{
	size_t i;
	va_list arcs;

	if (oid->num != num) {
		return 0;
	}

	va_start(arcs, num);
	for (i = 0; i < num; i++) {
		asn1_oid_arc_t arc = va_arg(arcs, asn1_oid_arc_t);

		if (oid->arcs[i] != arc) {
			return 0;
		}
	}
	va_end(arcs);

	return 1;
}

int
asn1_oid_cmp(const asn1_oid_t *a, const asn1_oid_t *b)
{
	// TODO: What happens if arcs are of different length?
	return memcmp(a->arcs, b->arcs, ASN1_OID_MAXIMUM_DEPTH);
}
