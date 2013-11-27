/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __ASININE_TEST_H__
#define __ASININE_TEST_H__

#include <stdio.h>

#define __test_line_no(line) __test_line_nox(line)
#define __test_line_nox(line) #line

#define check_msg(expr, msg) do { \
		if (!(expr)) return msg; \
	} while (0)

#define check_loc(expr, msg_) \
	check_msg(expr, __FILE__ ":" __test_line_no(__LINE__) ": " msg_)

#define check(expr) \
	check_loc(expr, #expr)

#define declare_set int failed_tests = 0;
#define end_set return failed_tests;

#define run_test(test) do { \
		const char *message = test(); \
		if (tests_run != NULL) (*tests_run)++; \
		if (message) { failed_tests++; printf("> %s\n", message); } \
	} while (0)

#endif /* __ASININE_TEST_H__ */
