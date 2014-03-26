/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <string.h>
#include <assert.h>
#include <stdio.h>

#include "asinine/asn1.h"

#define SECONDS_PER_YEAR  (31536000)
#define SECONDS_PER_MONTH  (2629744)
#define SECONDS_PER_DAY      (86400)
#define SECONDS_PER_HOUR      (3600)
#define SECONDS_PER_MINUTE      (60)

/** Y, M, D, H, "Z" */
#define MIN_DATA_LEN (4 * 2 + 1)

static bool
validate_string(const asn1_token_t *token)
{
	const uint8_t* data;
	const uint8_t* const data_end = token->data + token->length;

	if (token == NULL || token->type.class != ASN1_CLASS_UNIVERSAL) {
		return false;
	}

	switch (token->type.tag) {
		case ASN1_TAG_PRINTABLESTRING:
			for (data = token->data; data < data_end; data++) {
				// Space
				if (*data == 0x20) {
					continue;
				}

				// ' and z
				if (*data < 0x27 || *data > 0x7a) {
					return false;
				}

				// Illegal characters: *, ;, <, >, @
				if (*data == 0x2a || *data == 0x3b || *data == 0x3c
					|| *data == 0x3e || *data == 0x40) {
					return false;
				}
			}
			break;

		case ASN1_TAG_IA5STRING:
		case ASN1_TAG_VISIBLESTRING:
		case ASN1_TAG_T61STRING:
			for (data = token->data; data < data_end; data++) {
				/* Strictly speaking, control codes are allowed for IA5STRING,
				 * but since we don't have a way of dealing with code-page
				 * switching we restrict the type. This is non-conformant to the
				 * spec. Same goes for T61String, which can switch code pages
				 * mid-stream. We assume that the initial code-page is #6
				 * (ASCII), and flag switching as an error.
				 */
				if (*data < 0x20 || *data > 0x7f) {
					return false;
				}
			}
			break;

		case ASN1_TAG_UTF8STRING: {
			enum {
				LEADING,
				CONTINUATION
			} state;
			int bytes;

			state = LEADING;
			bytes = 0;

			for (data = token->data; data < data_end; data++) {
				uint8_t byte = *data;

				switch (state) {
					case LEADING: {
						if (byte < 0x80) {
							continue;
						}

						if (0xC2 <= byte && byte < 0xD0) {
							bytes = 1;
						} else if (0xD0 <= byte && byte < 0xF5) {
							bytes = (byte >> 4) - 0xC;
						} else {
							// 0x80 - 0xBF: Continuation bytes
							// 0xC0 - 0xC1: Invalid code points
							return false;
						}

						state = CONTINUATION;
						break;
					}

					case CONTINUATION: {
						if (0x80 <= byte && byte < 0xC0) {
							bytes -= 1;

							if (bytes == 0) {
								state = LEADING;
							}

							continue;
						}

						return false;
					}
				}
			}
			break;
		}

		default:
			return false;
	}

	return true;
}

// 8.23
asinine_err_t
asn1_string(const asn1_token_t *token, char *buf, const size_t num)
{
	if (!validate_string(token)) {
		return ASININE_ERROR_MALFORMED;
	}

	if (num <= token->length) {
		return ASININE_ERROR_MEMORY;
	}

	memcpy(buf, token->data, token->length);
	buf[token->length] = '\0';

	// We disallow NULLs in all strings, since the potential for abuse is too
	// high. This is a deviation from spec, obviously.
	if (strlen(buf) != token->length) {
		return ASININE_ERROR_INVALID;
	}

	return ASININE_OK;
}

bool
asn1_string_eq(const asn1_token_t *token, const char *str)
{
	if (!validate_string(token)) {
		return false;
	}

	if (token->length != strlen(str)) {
		return false;
	}

	return (memcmp(token->data, str, token->length) == 0);
}

// 8.6
asinine_err_t
asn1_bitstring(const asn1_token_t *token, uint8_t *buf, const size_t num)
{
	// Thank you http://stackoverflow.com/a/2603254
	static const uint8_t lookup[16] = {
		0x0, 0x8, 0x4, 0xC,
		0x2, 0xA, 0x6, 0xE,
		0x1, 0x9, 0x5, 0xD,
		0x3, 0xB, 0x7, 0xF
	};

	/* First byte is number of unused bits in the last byte, must be <= 7. Last
	 * byte must not be 0, since it is not the smallest possible encoding.
	 * An empty bitstring is encoded as first byte 0 and no further data.
	 */
	uint8_t unused_bits;
	size_t i, j;

	// 8.6.2.2 and 10.2
	if (token->length < 1 || token->type.encoding != ASN1_ENCODING_PRIMITIVE) {
		return ASININE_ERROR_MALFORMED;
	}

	if (token->length - 1 > num) {
		return ASININE_ERROR_MEMORY;
	}

	memset(buf, 0, num);
	unused_bits = token->data[0];

	// 8.6.2.2
	if (unused_bits > 7) {
		return ASININE_ERROR_MALFORMED;
	}

	// 8.6.2.3
	if (token->length == 1) {
		return (unused_bits == 0) ? ASININE_OK : ASININE_ERROR_MALFORMED;
	}

	// 11.2.2
	if (token->data[token->length - 1] == 0) {
		return ASININE_ERROR_MALFORMED;
	}

	// 11.2.1
	if (unused_bits > 0) {
		unused_bits = (1 << unused_bits) - 1;

		if ((token->data[token->length - 1] & unused_bits) != 0) {
			return ASININE_ERROR_MALFORMED;
		}
	}

	for (i = 1, j = 0; i < token->length; i++, j++) {
		const uint8_t data = token->data[i];

		buf[j] = (lookup[data & 0xf] << 4) | lookup[data >> 4];
	}

	return ASININE_OK;
}

// 8.3
asinine_err_t
asn1_int(const asn1_token_t *token, int *value)
{
	const uint8_t *data = token->data;
	bool negative;

	if (token->length == 0) {
		return ASININE_ERROR_INVALID;
	}

	if (token->length > sizeof *value) {
		return ASININE_ERROR_MEMORY;
	}

	negative = *data & 0x80;
	*value = *data & 0x7F;

	if (token->length > 1) {
		const uint8_t* const end = token->data + token->length;

		// 8.3.2
		uint16_t leading = ((data[0] << 8) | data[1]) >> 7;

		if (leading == 0 || leading == (1<<9)-1) {
			return ASININE_ERROR_MALFORMED;
		}

		for (data += 1; data < end; data++) {
			*value = (*value << 8) | *data;
		}
	}

	// http://graphics.stanford.edu/~seander/bithacks.html#ConditionalNegate
	*value = (*value ^ -negative) + negative;

	return ASININE_OK;
}

static bool
decode_pair(const char *data, int *pair)
{
	if (data[0] < 0x30 || data[0] > 0x39 || data[1] < 0x30 || data[1] > 0x39) {
		return false;
	}

	*pair = (data[0] - 0x30) * 10 + (data[1] - 0x30);
	return true;
}

asinine_err_t
asn1_time(const asn1_token_t *token, asn1_time_t *time)
{
	// YYMMDDHHMM(SS)(Z|+-D)
	static const uint8_t days_per_month[12] = {
		// Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec
		    31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
	};

	const char *data = (char *)token->data;

	union {
		struct part {
			int year;
			int month;
			int day;
			int hour;
			int minute;
			int second;
		} part;
		int raw[6];
	} t;
	struct part *part = &t.part;

	int i;
	int is_leap, leap_days;

	part->year = part->month = part->day = part->hour = part->minute =
		part->second = -1;

	if (token->length < MIN_DATA_LEN) {
		return ASININE_ERROR_MALFORMED;
	}

	for (i = 0; i < 5; data += 2, i++) {
		if (!decode_pair(data, &t.raw[i])) {
			return ASININE_ERROR_MALFORMED;
		}
	}

	// TODO: Support fractional seconds?
	// TODO: Section 11.7 specifies that time types need to
	// - truncate trailing zeros or omit fractional seconds including '.'
	// - use '.' as a fractional delimiter

	if (*data != 'Z') {
		// Try to decode seconds
		if (data + 2 >= (char*)(token->data + token->length)) {
			// Need at least another char for seconds, plus 'Z' or timezone
			return ASININE_ERROR_MALFORMED;
		}

		if (!decode_pair(data, &part->second)) {
			return ASININE_ERROR_MALFORMED;
		}
		data += 2;
	}

	if (*data != 'Z') {
		return ASININE_ERROR_MALFORMED;
	}

	// Validation
	if (token->type.tag == ASN1_TAG_UTCTIME) {
		// Years are from (19)50 to (20)49, so 99 is 1999 and 00 is 2000.
		if (part->year < 0 || part->year > 99) {
			return ASININE_ERROR_MALFORMED;
		}

		// Normalize years, since the encoding is not linear:
		// 00 -> 2000, 49 -> 2049, 50 -> 1950, 99 -> 1999
		part->year += (part->year > 49) ? 1900 : 2000;
	} else {
		return ASININE_ERROR_MALFORMED;
	}

	is_leap = part->year % 4 == 0 &&
		(part->year % 100 != 0 || part->year % 400 == 0);

	if (part->month < 1 || part->month > 12) {
		return ASININE_ERROR_MALFORMED;
	}

	if (part->day < 1) {
		return ASININE_ERROR_MALFORMED;
	} else if (is_leap && part->month == 2) {
		// Check February in leap years
		if (part->day > 29) {
			return ASININE_ERROR_MALFORMED;
		}
	} else if (part->day > days_per_month[part->month - 1]) {
		return ASININE_ERROR_MALFORMED;
	}

	if (part->hour < 0 || part->hour > 23) {
		return ASININE_ERROR_MALFORMED;
	}

	if (part->second < 0 || part->second > 59) {
		return ASININE_ERROR_MALFORMED;
	}

	// Convert to UNIX time (approximately)
	leap_days = (part->year - 1968) / 4 - (part->year - 1900) / 100 +
		(part->year - 1600) / 400;

	if (is_leap && part->month < 3) {
		// Do not add leap day if current year is leap year and date specified
		// is before March 1st
		leap_days -= 1;
	}

	part->year  -= 1970;
	part->month -= 1;
	part->day   -= 1;

	*time = part->year * SECONDS_PER_YEAR;

	for (i = 0; i < part->month; i++) {
		*time += days_per_month[i] * SECONDS_PER_DAY;
	}

	*time += part->day  * SECONDS_PER_DAY;
	*time += part->hour * SECONDS_PER_HOUR;
	*time += part->minute * SECONDS_PER_MINUTE;
	*time += part->second;

	*time += leap_days * SECONDS_PER_DAY;

	return ASININE_OK;
}

asinine_err_t
asn1_bool(const asn1_token_t *token, bool *value)
{
	uint8_t data;

	if (token->length != 1) {
		return ASININE_ERROR_MALFORMED;
	}

	data = *token->data;
	// 11.1
	if (data == 0x00) {
		*value = false;
	} else if (data == 0xFF) {
		*value = true;
	} else {
		return ASININE_ERROR_MALFORMED;
	}

	return ASININE_OK;
}

asinine_err_t
asn1_null(const asn1_token_t* token)
{
	return (token->length == 0) ? ASININE_OK : ASININE_ERROR_MALFORMED;
}

const char*
asinine_err_to_string(asinine_err_t err)
{
#define case_for_tag(x) case x: return #x
	switch (err) {
		case_for_tag(ASININE_OK);
		case_for_tag(ASININE_ERROR_MALFORMED);
		case_for_tag(ASININE_ERROR_MEMORY);
		case_for_tag(ASININE_ERROR_UNSUPPORTED);
		case_for_tag(ASININE_ERROR_UNSUPPORTED_ALGO);
		case_for_tag(ASININE_ERROR_UNSUPPORTED_EXTN);
		case_for_tag(ASININE_ERROR_INVALID);
		case_for_tag(ASININE_ERROR_INVALID_UNTRUSTED);
		case_for_tag(ASININE_ERROR_INVALID_EXPIRED);
		default: return "UNKNOWN";
	}
#undef case_for_tag
}

static const char*
class_to_string(asn1_class_t class)
{
#undef case_for
#define case_for(x) case x: return #x
	switch ((asn1_class_t)class) {
		case_for(ASN1_CLASS_UNIVERSAL);
		case_for(ASN1_CLASS_APPLICATION);
		case_for(ASN1_CLASS_CONTEXT);
		case_for(ASN1_CLASS_PRIVATE);
		default: return "UNKNOWN";
	}
#undef case_for
}

static const char*
tag_to_string(asn1_tag_t tag)
{
#undef case_for
#define case_for(x) case x: return #x
	switch((asn1_tag_t)tag) {
		case_for(ASN1_TAG_BOOL);
		case_for(ASN1_TAG_INT);
		case_for(ASN1_TAG_BITSTRING);
		case_for(ASN1_TAG_OCTETSTRING);
		case_for(ASN1_TAG_NULL);
		case_for(ASN1_TAG_OID);
		case_for(ASN1_TAG_UTF8STRING);
		case_for(ASN1_TAG_SEQUENCE);
		case_for(ASN1_TAG_SET);
		case_for(ASN1_TAG_PRINTABLESTRING);
		case_for(ASN1_TAG_T61STRING);
		case_for(ASN1_TAG_IA5STRING);
		case_for(ASN1_TAG_UTCTIME);
		case_for(ASN1_TAG_GENERALIZEDTIME);
		case_for(ASN1_TAG_VISIBLESTRING);
		default: return "UNKNOWN";
	}
#undef case_for
}

size_t
asn1_to_string(char *dst, size_t num, const asn1_type_t* type)
{
	if (type->class == ASN1_CLASS_UNIVERSAL) {
		return snprintf(dst, num, "%s", tag_to_string(type->tag));
	} else {
		const char* class = class_to_string(type->class);
		return snprintf(dst, num, "%s:%d", class, type->tag);
	}
}

const uint8_t*
asn1_raw(const asn1_token_t *token)
{
	if (token->data == NULL || token->length == 0) {
		return NULL;
	}

	return token->data;
}

static inline bool
type_eq(const asn1_type_t* type, asn1_class_t class, asn1_tag_t tag,
	asn1_encoding_t encoding)
{
	return (type->class == class) && (type->tag == tag) &&
	       (type->encoding == encoding);
}

bool
asn1_eq(const asn1_token_t* a, const asn1_token_t* b)
{
	assert(a != NULL);
	assert(b != NULL);

	return (a->length == b->length) &&
	       type_eq(&a->type, b->type.class, b->type.tag, b->type.encoding) &&
	       // Since passing NULL to memcmp is UB we check for pointer equality:
	       // 1. Only length == 0 can have NULL data ptrs
	       // 2. By this point length has to be equal: either both or none NULL
	       // 3. NULL ptrs will be caught by the first case of this clause
	       ((a->data == b->data) || memcmp(a->data, b->data, a->length) == 0);
}

bool
asn1_is(const asn1_token_t *token, asn1_class_t class, asn1_tag_t tag,
	asn1_encoding_t encoding)
{
	assert(token != NULL);

	return type_eq(&token->type, class, tag, encoding);
}

bool
asn1_is_time(const asn1_token_t *token)
{
	assert(token != NULL);

	return type_eq(&token->type, ASN1_CLASS_UNIVERSAL, ASN1_TAG_UTCTIME,
		ASN1_ENCODING_PRIMITIVE);
}

bool
asn1_is_string(const asn1_token_t *token)
{
	assert(token != NULL);

	return (token->type.class == ASN1_CLASS_UNIVERSAL) &&
	       (token->type.tag == ASN1_TAG_PRINTABLESTRING ||
	       token->type.tag == ASN1_TAG_IA5STRING ||
	       token->type.tag == ASN1_TAG_UTF8STRING ||
	       token->type.tag == ASN1_TAG_VISIBLESTRING ||
	       token->type.tag == ASN1_TAG_T61STRING) &&
	       (token->type.encoding == ASN1_ENCODING_PRIMITIVE);
}

bool
asn1_is_sequence(const asn1_token_t *token)
{
	return asn1_is(token, ASN1_CLASS_UNIVERSAL, ASN1_TAG_SEQUENCE,
		ASN1_ENCODING_CONSTRUCTED);
}

bool
asn1_is_oid(const asn1_token_t *token)
{
	return asn1_is(token, ASN1_CLASS_UNIVERSAL, ASN1_TAG_OID,
		ASN1_ENCODING_PRIMITIVE);
}

bool
asn1_is_int(const asn1_token_t *token)
{
	return asn1_is(token, ASN1_CLASS_UNIVERSAL, ASN1_TAG_INT,
		ASN1_ENCODING_PRIMITIVE);
}

bool
asn1_is_bool(const asn1_token_t *token)
{
	return asn1_is(token, ASN1_CLASS_UNIVERSAL, ASN1_TAG_BOOL,
		ASN1_ENCODING_PRIMITIVE);
}

bool
asn1_is_set(const asn1_token_t *token)
{
	return asn1_is(token, ASN1_CLASS_UNIVERSAL, ASN1_TAG_SET,
		ASN1_ENCODING_CONSTRUCTED);
}

bool
asn1_is_bitstring(const asn1_token_t *token)
{
	return asn1_is(token, ASN1_CLASS_UNIVERSAL, ASN1_TAG_BITSTRING,
		ASN1_ENCODING_PRIMITIVE);
}

bool
asn1_is_octetstring(const asn1_token_t *token)
{
	return asn1_is(token, ASN1_CLASS_UNIVERSAL, ASN1_TAG_OCTETSTRING,
		ASN1_ENCODING_PRIMITIVE);
}

bool
asn1_is_null(const asn1_token_t *token)
{
	return asn1_is(token, ASN1_CLASS_UNIVERSAL, ASN1_TAG_NULL,
		ASN1_ENCODING_PRIMITIVE);
}
