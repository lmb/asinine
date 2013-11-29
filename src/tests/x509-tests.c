/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "asinine/x509.h"

#include "asinine/test.h"
#include "asinine/tests/x509.h"
#include "asinine/tests/certs.h"

static char*
test_x509_parse(void)
{
	x509_cert_t cert;
	size_t i;
	bool errors;

	for (errors = false, i = 0; i < x509_certs_num; i++) {
		const uint8_t * const data = x509_certs[i].data;
		const size_t length = x509_certs[i].length;

		if (x509_parse(&cert, data, length) != X509_OK) {
			errors = true;

			printf("> %s (#%lu) failed to parse\n", x509_certs[i].host, i);
		}
	}

	check(x509_parse(&cert, x509_certs[0].data, x509_certs[0].length) == X509_OK);

	return (!errors) ? 0 : "Some certificates failed to parse";
}

int
test_x509_all(int *tests_run)
{
	declare_set;

	run_test(test_x509_parse);

	end_set;
}
