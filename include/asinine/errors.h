/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#define ERROR(e, r) \
	(asinine_err_t) { .errno = e, .reason = r }

#define RETURN_ON_ERROR(expr) \
	do { \
		asinine_err_t ret_##__LINE__ = expr; \
		if (ret_##__LINE__.errno != ASININE_OK) { \
			return ret_##__LINE__; \
		} \
	} while (0)
