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

	check(x509_parse(&cert, x509_certs[0].data, x509_certs[0].length) == X509_OK);

	return 0;
}

int
test_x509_all(int *tests_run)
{
	declare_set;

	run_test(test_x509_parse);

	end_set;
}
