/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#define RETURN_ON_ERROR(expr) \
	do { \
		asinine_err_t ret__##__LINE__ = expr; \
		if (ret__##__LINE__ != ASININE_OK) { \
			return ret__##__LINE__; \
		} \
	} while (0)
#define NEXT_TOKEN(parser) RETURN_ON_ERROR(asn1_next(parser))
#define NEXT_CHILD(parser) \
	do { \
		if (asn1_eof(parser)) { \
			return asn1_pop(parser); \
		} \
		NEXT_TOKEN(parser); \
	} while (0)
