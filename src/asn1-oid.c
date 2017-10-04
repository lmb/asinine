/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "asinine/asn1.h"
#include "asinine/errors.h"
#include "internal/macros.h"

#define OID_MINIMUM_ARCS 2

#define OID_CONTINUATION_MASK (1 << 7)
#define OID_VALUE_MASK ((1 << 7) - 1)
#define OID_VALUE_BITS_PER_BYTE 7

static bool
append_arc(asn1_oid_t *oid, asn1_oid_arc_t arc) {
	if (oid->num >= NUM(oid->arcs)) {
		return false;
	}

	oid->arcs[oid->num++] = arc;
	return true;
}

// 8.19
asinine_err_t
asn1_oid(const asn1_token_t *token, asn1_oid_t *oid) {
	asn1_oid_arc_t arc;
	bool is_first_arc;
	size_t arc_bits;
	const uint8_t *data;

	// Zero every OID so that asn1_oid_cmp works
	*oid = (asn1_oid_t){0};

	if (token->data == NULL || token->length == 0) {
		return ERROR(ASININE_ERR_MALFORMED, "OID: zero length");
	}

	// 8.19.2 "[...] last in the series: bit 8 of the last octet is zero; [...]"
	// Since we need to have the end of a series at the end of this token, we
	// check here.
	if ((*(token->data + token->length - 1) & OID_CONTINUATION_MASK) != 0) {
		return ERROR(ASININE_ERR_MALFORMED, "OID: no end marker");
	}

	arc          = 0;
	arc_bits     = 0;
	is_first_arc = true;

	for (data = token->data; data < token->data + token->length; data++) {
		if (arc == 0 && *data == 0x80) {
			// 8.19.2 "the leading octet of the subidentifier shall not have the
			// value 0x80"
			return ERROR(ASININE_ERR_MALFORMED, "OID: leading byte is zero");
		}

		arc = (arc << OID_VALUE_BITS_PER_BYTE) | (*data & OID_VALUE_MASK);
		arc_bits += OID_VALUE_BITS_PER_BYTE;

		if (arc_bits > sizeof(arc) * 8) {
			return ERROR(ASININE_ERR_MEMORY, "OID: arc too long");
		}

		if ((*data & OID_CONTINUATION_MASK) == 0) {
			if (is_first_arc) {
				// 8.19.4 + .5
				// If first arc is 2, values > 39 can be encoded for the second
				// one.
				asn1_oid_arc_t x = MIN(arc, 80) / 40;

				if (!append_arc(oid, x)) {
					return ERROR(ASININE_ERR_MEMORY, "OID: too many arcs");
				}

				arc          = (arc - (x * 40));
				is_first_arc = 0;
			}

			if (!append_arc(oid, arc)) {
				return ERROR(ASININE_ERR_MEMORY, "OID: too many arcs");
			}

			arc      = 0;
			arc_bits = 0;
		}
	}

	return ERROR(ASININE_OK, NULL);
}

static size_t
arc_digits(asn1_oid_arc_t num) {
	size_t digits = 1;
	while (num / 10 > 0) {
		digits++;
		num /= 10;
	}
	return digits;
}

static size_t
format_arc(char *buffer, size_t len, asn1_oid_arc_t arc) {
	size_t digits = arc_digits(arc);

	if (digits < len) {
		buffer[digits] = '.';
	}

	for (size_t i = digits; i > 0; i--) {
		char digit = (char)(arc % 10) + '0';
		arc /= 10;
		if (i - 1 < len) {
			buffer[i - 1] = digit;
		}
	}

	return digits + 1;
}

size_t
asn1_oid_to_string(char *buffer, size_t len, const asn1_oid_t *oid) {
	if (oid->num == 0) {
		if (len > 0) {
			buffer[0] = '\0';
		}
		return 0;
	}

	size_t required  = 0;
	size_t remaining = len;

	for (size_t i = 0; i < oid->num; i++) {
		asn1_oid_arc_t arc = oid->arcs[i];
		size_t n           = format_arc(buffer, remaining, arc);

		required += n;

		if (n > remaining) {
			buffer += remaining;
			remaining = 0;
			continue;
		}

		buffer += n;
		remaining -= n;
	}

	if (len > 0) {
		*(buffer - 1) = '\0';
	}

	return required - 1;
}

bool
asn1_oid_eq(const asn1_oid_t *oid, size_t num, ...) {
	size_t i;
	va_list arcs;

	if (oid->num != num) {
		return false;
	}

	va_start(arcs, num);
	for (i = 0; i < num; i++) {
		asn1_oid_arc_t arc = va_arg(arcs, asn1_oid_arc_t);

		if (oid->arcs[i] != arc) {
			return false;
		}
	}
	va_end(arcs);

	return true;
}

int
asn1_oid_cmp(const asn1_oid_t *a, const asn1_oid_t *b) {
	size_t num = a->num;
	if (num > b->num) {
		num = b->num;
	}

	for (size_t i = 0; i < num; ++i) {
		if (a->arcs[i] != b->arcs[i]) {
			return (a->arcs[i] > b->arcs[i]) - (a->arcs[i] < b->arcs[i]);
		}
	}

	return (a->num > b->num) - (a->num < b->num);
}
