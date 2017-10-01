/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>

#include "asinine/asn1.h"
#include "asinine/macros.h"
#include "internal/macros.h"
#include "tests/asn1.h"
#include "tests/test.h"

#define TEST_OID1 ASN1_CONST_OID(1, 1, 2, 4)
#define TEST_OID2 ASN1_CONST_OID(2, 999, 1)

static char *
test_asn1_oid_decode(void) {
	static const uint8_t raw[] = {SEQ(OID(0x29, 0x02, 0x04), // TEST_OID1
	    OID(0x88, 0x37, 0x01)                                // TEST_OID2
	    )};

	asn1_parser_t parser;
	asn1_oid_t oid;

	asn1_init(&parser, raw, sizeof(raw));

	check_OK(asn1_next(&parser));
	check_OK(asn1_push(&parser));

	check_OK(asn1_next(&parser));
	check_OK(asn1_oid(&parser.token, &oid));
	check(asn1_oid_eq(&oid, TEST_OID1));

	check_OK(asn1_next(&parser));
	check_OK(asn1_oid(&parser.token, &oid));
	check(asn1_oid_eq(&oid, TEST_OID2));

	check_OK(asn1_pop(&parser));
	check(asn1_eof(&parser));

	return 0;
}

static char *
test_asn1_oid_decode_invalid(void) {
	static const uint8_t invalid_padding[] = {
	    SEQ(OID(0x01, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7F), OID(0x80, 0x01),
	        OID(0x80, 0x7F), EMPTY_OID())};

	asn1_parser_t parser;
	asn1_oid_t oid;

	asn1_init(&parser, invalid_padding, sizeof(invalid_padding));

	check_OK(asn1_next(&parser));
	check_OK(asn1_push(&parser));

	check_OK(asn1_next(&parser));
	check(asn1_oid(&parser.token, &oid).errno == ASININE_ERR_MALFORMED);

	check_OK(asn1_next(&parser));
	check(asn1_oid(&parser.token, &oid).errno == ASININE_ERR_MALFORMED);

	check_OK(asn1_next(&parser));
	check(asn1_oid(&parser.token, &oid).errno == ASININE_ERR_MALFORMED);

	check_OK(asn1_next(&parser));
	check(asn1_oid(&parser.token, &oid).errno == ASININE_ERR_MALFORMED);

	check_OK(asn1_pop(&parser));
	check(asn1_eof(&parser));

	return 0;
}

static char *
test_asn1_oid_to_string(void) {
	char oid_str[128];
	const asn1_oid_t oid   = ASN1_OID(1, 2, 123);
	const asn1_oid_t empty = {0};

	check(asn1_oid_to_string(oid_str, sizeof(oid_str), &oid) == 7);
	check(strncmp("1.2.123", oid_str, sizeof(oid_str)) == 0);

	check(asn1_oid_to_string(oid_str, 6, &oid) == 7);
	check(strncmp("1.2.1", oid_str, sizeof(oid_str)) == 0);

	check(asn1_oid_to_string(oid_str, sizeof(oid_str), &empty) == 0);
	check(strncmp("", oid_str, sizeof(oid_str)) == 0);

	return 0;
}

static char *
test_asn1_oid_comparison(void) {
	const asn1_oid_t a = ASN1_OID_FROM_CONST(TEST_OID1);
	const asn1_oid_t b = ASN1_OID(1, 1, 3, 4);
	const asn1_oid_t c = ASN1_OID(1, 1, 2, 4, 1);

	check(asn1_oid_eq(&a, TEST_OID1));
	check(!asn1_oid_eq(&b, TEST_OID1));

	check(asn1_oid_cmp(&a, &a) == 0);
	check(asn1_oid_cmp(&a, &b) < 0);
	check(asn1_oid_cmp(&b, &c) > 0);

	return 0;
}

static char *
test_asn1_bitstring_decode(void) {
	const uint8_t valid1[] = {0x04, 0xaa, 0xf0};
	const uint8_t valid2[] = {0x00};

	const asn1_token_t token1 =
	    TOKEN(ASN1_TAG_BITSTRING, valid1, ASN1_ENCODING_PRIMITIVE);
	const asn1_token_t token2 =
	    TOKEN(ASN1_TAG_BITSTRING, valid2, ASN1_ENCODING_PRIMITIVE);

	uint8_t buf[2];

	check_OK(asn1_bitstring(&token1, buf, sizeof buf));
	check(buf[0] == 0x55);
	check(buf[1] == 0x0f);

	check_OK(asn1_bitstring(&token2, buf, sizeof buf));
	check(buf[0] == 0);
	check(buf[1] == 0);

	check_OK(asn1_bitstring(&token2, NULL, 0));

	return 0;
}

static char *
test_asn1_bitstring_decode_invalid(void) {
	const uint8_t invalid1[] = {0x04, 0x0f};
	const uint8_t invalid2[] = {0xff, 0x0f};
	const uint8_t invalid3[] = {0x01};
	const uint8_t invalid4[] = {0x00, 0x00};

	const asn1_token_t token2 =
	    TOKEN(ASN1_TAG_BITSTRING, invalid1, ASN1_ENCODING_PRIMITIVE);
	const asn1_token_t token3 =
	    TOKEN(ASN1_TAG_BITSTRING, invalid2, ASN1_ENCODING_PRIMITIVE);
	const asn1_token_t token4 =
	    TOKEN(ASN1_TAG_BITSTRING, invalid3, ASN1_ENCODING_PRIMITIVE);
	const asn1_token_t token5 =
	    TOKEN(ASN1_TAG_BITSTRING, invalid4, ASN1_ENCODING_PRIMITIVE);

	uint8_t buf[1];

	check(asn1_bitstring(&token2, buf, 0).errno == ASININE_ERR_MEMORY);
	check(asn1_bitstring(&token2, buf, sizeof buf).errno ==
	      ASININE_ERR_MALFORMED);
	check(asn1_bitstring(&token3, buf, sizeof buf).errno ==
	      ASININE_ERR_MALFORMED);
	check(asn1_bitstring(&token4, buf, sizeof buf).errno ==
	      ASININE_ERR_MALFORMED);
	check(asn1_bitstring(&token5, buf, sizeof buf).errno ==
	      ASININE_ERR_MALFORMED);

	return 0;
}

static char *
test_asn1_parse(void) {
	static const uint8_t raw[] = {SEQ( // 0
	    SEQ(                           // 1
	        INT(0x01),                 // 2
	        INT(0x02)                  // 3
	        ),
	    INT(0xFF),              // 4
	    SEQ(INT(0x11)),         // 5 (6)
	    SEQ(                    // 7
	        INT(0x01),          // 8
	        SEQ(                // 9
	            SEQ(INT(0x02)), // 10 (11)
	            INT(0x03)       // 12
	            )),
	    EMPTY_SEQ() // 13
	    )};

	asn1_parser_t parser;
	asn1_word_t value;

	asn1_init(&parser, raw, sizeof(raw));

	// 0
	check_OK(asn1_next(&parser));
	check(asn1_is_sequence(&parser.token));
	check_OK(asn1_push(&parser));

	// 1
	check_OK(asn1_next(&parser));
	check(asn1_is_sequence(&parser.token));
	check_OK(asn1_push(&parser));

	// 2
	check_OK(asn1_next(&parser));
	check(asn1_is_int(&parser.token));
	check_OK(asn1_int(&parser.token, &value));
	check(value == 0x01);

	// 3
	check_OK(asn1_next(&parser));
	check(asn1_is_int(&parser.token));
	check_OK(asn1_int(&parser.token, &value));
	check(value == 0x02);

	check_OK(asn1_pop(&parser));

	// 4
	check_OK(asn1_next(&parser));
	check(asn1_is_int(&parser.token));
	check_OK(asn1_int(&parser.token, &value));
	check(value == -1);

	// 5
	check_OK(asn1_next(&parser));
	check(asn1_is_sequence(&parser.token));
	check_OK(asn1_push(&parser));

	// 6
	check_OK(asn1_next(&parser));
	check(asn1_is_int(&parser.token));
	check_OK(asn1_int(&parser.token, &value));
	check(value == 0x11);

	check_OK(asn1_pop(&parser));

	// 7
	check_OK(asn1_next(&parser));
	check(asn1_is_sequence(&parser.token));
	check_OK(asn1_push(&parser));

	// 8
	check_OK(asn1_next(&parser));
	check(asn1_is_int(&parser.token));
	check_OK(asn1_int(&parser.token, &value));
	check(value == 0x01);

	// 9
	check_OK(asn1_next(&parser));
	check(asn1_is_sequence(&parser.token));
	check_OK(asn1_push(&parser));

	// 10
	check_OK(asn1_next(&parser));
	check(asn1_is_sequence(&parser.token));
	check_OK(asn1_push(&parser));

	// 11
	check_OK(asn1_next(&parser));
	check(asn1_is_int(&parser.token));
	check_OK(asn1_int(&parser.token, &value));
	check(value == 0x02);

	check_OK(asn1_pop(&parser));

	// 12
	check_OK(asn1_next(&parser));
	check(asn1_is_int(&parser.token));
	check_OK(asn1_int(&parser.token, &value));
	check(value == 0x03);

	check_OK(asn1_pop(&parser));
	check_OK(asn1_pop(&parser));

	// 13
	check_OK(asn1_next(&parser));
	check(asn1_is_sequence(&parser.token));

	check(asn1_eof(&parser));

	return 0;
}

static char *
test_asn1_parse_nested(void) {
	const uint8_t raw[] = {SEQ( // 1
	    SEQ(                    // 2
	        INT(0x01), SEQ(INT(0x02)), INT(0x03), SEQ(INT(0x04))),
	    INT(0x05),
	    SEQ( // 2
	        INT(0x06), SEQ(INT(0x07)), INT(0x08), SEQ(INT(0x09))),
	    INT(0x0A))};

	asn1_parser_t parser;
	asn1_word_t value, test = 1;

	asn1_init(&parser, raw, sizeof raw);

	check_OK(asn1_next(&parser));
	check_OK(asn1_push(&parser));
	while (!asn1_eof(&parser)) { // 1
		check_OK(asn1_next(&parser));
		check_OK(asn1_push(&parser));
		while (!asn1_eof(&parser)) { // 2
			check_OK(asn1_next(&parser));
			check_OK(asn1_int(&parser.token, &value));
			check(value == test);
			test++;

			check_OK(asn1_next(&parser));
			check_OK(asn1_push(&parser));

			check_OK(asn1_next(&parser));
			check_OK(asn1_int(&parser.token, &value));
			check(value == test);
			test++;

			check_OK(asn1_pop(&parser));
		}
		check_OK(asn1_pop(&parser));

		check_OK(asn1_next(&parser));
		check_OK(asn1_int(&parser.token, &value));
		check(value == test);
		test++;
	}
	check_OK(asn1_pop(&parser));

	check(asn1_eof(&parser));

	return 0;
}

static char *
test_asn1_parse_longform(void) {
	// Long-form, 1 byte length, 128 bytes
	const uint8_t raw[3 + 128] = {0x01, 0x80 | 0x01, 0x80};

	asn1_parser_t parser;
	asn1_init(&parser, raw, sizeof(raw));

	check_OK(asn1_next(&parser));
	check(parser.token.length == 128);

	return 0;
}

static char *
test_asn1_parse_single(void) {
	uint8_t raw1[2 + sizeof(int)] = {EMPTY_INT()};
	const uint8_t raw2[]          = {NUL()};

	asn1_word_t value;

	asn1_parser_t parser;

	raw1[1]               = (uint8_t)sizeof(int);
	raw1[2]               = 0x80;
	raw1[1 + sizeof(int)] = 0x01;

	asn1_init(&parser, raw1, sizeof raw1);
	check_OK(asn1_next(&parser));
	check(asn1_is_int(&parser.token));
	check_OK(asn1_int(&parser.token, &value));
	check(value == 1 - INT_MIN);
	check(asn1_eof(&parser));

	asn1_init(&parser, raw2, sizeof raw2);
	check_OK(asn1_next(&parser));
	check(asn1_is_null(&parser.token));
	check(asn1_eof(&parser));

	return 0;
}

static char *
test_asn1_parse_invalid(void) {
	// Indefinite length
	const uint8_t invalid1[] = {0x06, 0x80};
	// Reserved
	const uint8_t invalid2[] = {0x06, 0xFF};
	// Garbage after root token
	const uint8_t invalid3[] = {NUL(), 0xDE, 0xAD, 0xBE, 0xEF};
	// Long-form, length < 128
	const uint8_t invalid4[] = {0x01, 0x80 | 0x01, 0x01};
	// Long-form, length too long
	const uint8_t invalid5[] = {
	    0x01, 0x80 | 0x0C, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00,
	};
	// Long-form, length encoding not of minimum length
	const uint8_t invalid6[] = {0x01, 0x80 | 0x03, 0x00, 0x01, 0x00};
	// Truncated token
	const uint8_t truncated[] = {0x01};
	// Max length overflow token, depends on length of size_t
	uint8_t max_length[] = {
	    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};

	asn1_parser_t parser;

	asn1_init(&parser, invalid1, sizeof(invalid1));
	check(asn1_next(&parser).errno == ASININE_ERR_MALFORMED);

	asn1_init(&parser, invalid2, sizeof(invalid2));
	check(asn1_next(&parser).errno == ASININE_ERR_MALFORMED);

	asn1_init(&parser, invalid3, sizeof(invalid3));
	check_OK(asn1_next(&parser));
	check(!asn1_eof(&parser));

	asn1_init(&parser, invalid4, sizeof(invalid4));
	check(asn1_next(&parser).errno == ASININE_ERR_MALFORMED);

	asn1_init(&parser, invalid5, sizeof(invalid5));
	check(asn1_next(&parser).errno == ASININE_ERR_UNSUPPORTED);

	asn1_init(&parser, invalid6, sizeof(invalid6));
	check(asn1_next(&parser).errno == ASININE_ERR_MALFORMED);

	asn1_init(&parser, truncated, sizeof(truncated));
	check(asn1_next(&parser).errno == ASININE_ERR_MALFORMED);

	// A token of max length overflowed the pointer bounds check
	max_length[1] = (uint8_t)sizeof parser.token.length;
	for (uint8_t i = 0; i < max_length[1]; i++) {
		max_length[2 + i] = 0xFF;
	}
	max_length[1] |= 0x80;

	asn1_init(&parser, max_length, sizeof(max_length));
	check(asn1_next(&parser).errno == ASININE_ERR_MALFORMED);

	return 0;
}

static char *
test_asn1_parse_time(void) {
	// Unix epoch
	const char epoch_raw[]         = "700101000000Z";
	const asn1_token_t epoch_token = STR_TOKEN(ASN1_TAG_UTCTIME, epoch_raw);

	// Y2K
	const char y2k_raw[]         = "000101000000Z";
	const asn1_token_t y2k_token = STR_TOKEN(ASN1_TAG_UTCTIME, y2k_raw);

	// February has 29 days in leap years
	const char leap_feb_raw[] = "000229000000Z";
	const asn1_token_t leap_feb_token =
	    STR_TOKEN(ASN1_TAG_UTCTIME, leap_feb_raw);

	// Y2K38
	const char y2k38_raw[]         = "380119031408Z";
	const asn1_token_t y2k38_token = STR_TOKEN(ASN1_TAG_UTCTIME, y2k38_raw);

	asn1_time_t time;

	check_OK(asn1_time(&epoch_token, &time));
	check(asn1_time_cmp(&time, &TIME(1970, 1, 1, 0, 0, 0)) == 0);

	check_OK(asn1_time(&y2k_token, &time));
	check(asn1_time_cmp(&time, &TIME(2000, 1, 1, 0, 0, 0)) == 0);

	check_OK(asn1_time(&leap_feb_token, &time));
	check(asn1_time_cmp(&time, &TIME(2000, 2, 29, 0, 0, 0)) == 0);

	check_OK(asn1_time(&y2k38_token, &time));
	check(asn1_time_cmp(&time, &TIME(2038, 1, 19, 3, 14, 8)) == 0);

	return 0;
}

static char *
test_asn1_parse_invalid_time(void) {
	// Garbage
	const char garbage_raw[]         = "ZYMMDDHHMMSS0";
	const asn1_token_t garbage_token = STR_TOKEN(ASN1_TAG_UTCTIME, garbage_raw);

	// Incomplete time
	const char incomplete_raw[] = "01010";
	const asn1_token_t incomplete_token =
	    STR_TOKEN(ASN1_TAG_UTCTIME, incomplete_raw);

	// Timezone needs to be specified
	const char missing_tz_raw[] = "010101010101";
	const asn1_token_t missing_tz_token =
	    STR_TOKEN(ASN1_TAG_UTCTIME, missing_tz_raw);

	// Midnight is encoded as 000000 (HHMMSS)
	const char midnight_raw[] = "100101240000Z";
	const asn1_token_t midnight_token =
	    STR_TOKEN(ASN1_TAG_UTCTIME, midnight_raw);

	// February only has 29 days in leap years (% 4 == 0)
	const char leap_year_raw[] = "010229000000Z";
	const asn1_token_t leap_year_token =
	    STR_TOKEN(ASN1_TAG_UTCTIME, leap_year_raw);

	// April only has 30 days
	const char days_raw[]         = "010431000000Z";
	const asn1_token_t days_token = STR_TOKEN(ASN1_TAG_UTCTIME, days_raw);

	asn1_time_t time;

	check(asn1_time(&garbage_token, &time).errno == ASININE_ERR_MALFORMED);
	check(asn1_time(&incomplete_token, &time).errno == ASININE_ERR_MALFORMED);
	check(asn1_time(&missing_tz_token, &time).errno == ASININE_ERR_MALFORMED);
	check(asn1_time(&midnight_token, &time).errno == ASININE_ERR_MALFORMED);
	check(asn1_time(&leap_year_token, &time).errno == ASININE_ERR_MALFORMED);
	check(asn1_time(&days_token, &time).errno == ASININE_ERR_MALFORMED);

	return 0;
}

static char *
test_asn1_parse_invalid_int(void) {
	const uint8_t leading_ones_raw[] = {0xFF, 0xFF};
	const asn1_token_t leading_ones_token =
	    TOKEN(ASN1_TAG_INT, leading_ones_raw, ASN1_ENCODING_PRIMITIVE);

	const uint8_t leading_zeroes_raw[] = {0x00, 0x01};
	const asn1_token_t leading_zeroes_token =
	    TOKEN(ASN1_TAG_INT, leading_zeroes_raw, ASN1_ENCODING_PRIMITIVE);

	check(asn1_int(&leading_ones_token, NULL).errno == ASININE_ERR_MALFORMED);
	check(asn1_int(&leading_zeroes_token, NULL).errno == ASININE_ERR_MALFORMED);

	return 0;
}

int
test_asn1_all(int *tests_run) {
	declare_set;

	printf("sizeof asn1_oid_t: %zu\n", sizeof(asn1_oid_t));
	printf("sizeof asn1_type_t: %zu\n", sizeof(asn1_type_t));
	printf("sizeof asn1_token_t: %zu\n", sizeof(asn1_token_t));
	printf("sizeof asn1_parser_t: %zu\n", sizeof(asn1_parser_t));

	run_test(test_asn1_oid_decode);
	run_test(test_asn1_oid_decode_invalid);
	run_test(test_asn1_oid_to_string);
	run_test(test_asn1_oid_comparison);
	run_test(test_asn1_bitstring_decode);
	run_test(test_asn1_bitstring_decode_invalid);
	run_test(test_asn1_parse);
	run_test(test_asn1_parse_nested);
	run_test(test_asn1_parse_longform);
	run_test(test_asn1_parse_single);
	run_test(test_asn1_parse_invalid);
	run_test(test_asn1_parse_time);
	run_test(test_asn1_parse_invalid_time);
	run_test(test_asn1_parse_invalid_int);

	end_set;
}
