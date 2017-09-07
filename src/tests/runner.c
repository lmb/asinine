/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdio.h>

#include "tests/asn1.h"
#include "tests/x509.h"

#define run_test_set(set) \
	do { \
		int failed_tests = set(&tests_run); \
		puts((failed_tests > 0) ? #set " FAILED\n" : #set " OK\n"); \
		total_failed_tests += failed_tests; \
	} while (0)

int
main(int argc, const char **argv) {
	int tests_run          = 0;
	int total_failed_tests = 0;

	(void)argc;
	(void)argv;

	run_test_set(test_asn1_all);
	run_test_set(test_x509_all);

	printf("Ran %u tests\n", tests_run);
	return total_failed_tests;
}
