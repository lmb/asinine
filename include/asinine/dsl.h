/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include "asinine/asn1.h"
#include "asinine/errors.h"

#define NEXT_TOKEN(parser) RETURN_ON_ERROR(asn1_next(parser))
#define OPTIONAL_TOKEN(parser) \
	do { \
		if (asn1_eof(parser)) { \
			return asn1_pop(parser); \
		} \
		NEXT_TOKEN(parser); \
	} while (0)
