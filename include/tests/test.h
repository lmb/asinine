/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <stdio.h>
#include <string.h>

#define __test_line_no(line) __test_line_nox(line)
#define __test_line_nox(line) #line

#define check_msg(expr, msg) \
	do { \
		if (!(expr)) \
			return msg; \
	} while (0)

#define check_loc(expr, msg_) \
	check_msg(expr, __FILE__ ":" __test_line_no(__LINE__) ": " msg_)

#define check(expr) check_loc(expr, #expr)
#define check_OK(expr) check((expr).errno == ASININE_OK)
#define check_ERROR(expr) check((expr).errno != ASININE_OK)

#define declare_set int failed_tests = 0;
#define end_set return failed_tests;

#define run_test(test) \
	do { \
		const char *message = test(); \
		if (tests_run != NULL) \
			(*tests_run)++; \
		if (message) { \
			failed_tests++; \
			printf("> %s\n", message); \
		} \
	} while (0)

#define TIME(_year, _month, _day, _hour, _minute, _second) \
	(asn1_time_t) { \
		.year = _year, .month = _month, .day = _day, .hour = _hour, \
		.minute = _minute, .second = _second \
	}
#define TOKEN_(tag_, dat, len, enc) \
	(asn1_token_t) { \
		.type = {.class = ASN1_CLASS_UNIVERSAL, \
		    .tag        = (tag_), \
		    .encoding   = (enc)}, \
		.data = (dat), .length = (len) \
	}
#define STR_TOKEN(tag, str) \
	TOKEN_(tag, (uint8_t *)(str), strlen(str), ASN1_ENCODING_PRIMITIVE)
#define TOKEN(tag, data, enc) TOKEN_(tag, data, sizeof(data), enc)

#define TYPE_(class, enc, tag) ((class << 6) | (enc << 5) | (tag))
#define SEQ_TYPE_ TYPE_(0, 1, 16)
#define SET_TYPE_ TYPE_(0, 1, 17)
#define INT_TYPE_ TYPE_(0, 0, 2)
#define OID_TYPE_ TYPE_(0, 0, 6)
#define STR_TYPE_ TYPE_(0, 0, 12)

#define RAW(tag, ...) tag, PP_NARG(__VA_ARGS__), __VA_ARGS__
#define EMPTY_RAW(tag) tag, 0x00
#define SEQ(...) RAW(SEQ_TYPE_, __VA_ARGS__)
#define EMPTY_SEQ() EMPTY_RAW(SEQ_TYPE_)
#define SET(...) RAW(SET_TYPE_, __VA_ARGS__)
#define INT(...) RAW(INT_TYPE_, __VA_ARGS__)
#define EMPTY_INT() EMPTY_RAW(INT_TYPE_)
#define OID(...) RAW(OID_TYPE_, __VA_ARGS__)
#define EMPTY_OID() EMPTY_RAW(OID_TYPE_)
#define NUL() EMPTY_RAW(TYPE_(0, 0, 5))
#define STR(...) RAW(STR_TYPE_, __VA_ARGS__)
#define EMPTY_STR(...) EMPTY_RAW(STR_TYPE_)
