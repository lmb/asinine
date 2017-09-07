/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

void hexdump(const uint8_t *buf, size_t num, int depth);
uint8_t *load(FILE *fd, size_t *length);
