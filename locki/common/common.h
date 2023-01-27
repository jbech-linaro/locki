/*
 * MIT License
 *
 * Copyright (c) 2023, Linaro Limited
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef	COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stddef.h>

#include <ta_locki.h>

#define MAX_KEY_SIZE 32

/* FIXME: Figure out why we cannot use the defines from util.h */
#ifndef BIT
#define BIT(nr)	(1 << (nr))
#endif
#define IS_SET(x, mask) ((x & mask) == mask)
#define IS_UNSET(x, mask) ((x & mask) == 0)

/*
 * Defines flags used when creating a user.
 */
#define USER_ADMIN			BIT(0)
#define USER_SALT_PASSWORD		BIT(1)
#define USER_UNAUTHENTICATED_MEASURE	BIT(2)
#define USER_TA_UNIQUE_PASSWORD		BIT(3)

#define USER_ALLOW_WRAPPED_KEY_EXPORT	BIT(4)
#define USER_ALLOW_UNAUTH_KEY_EXPORT	BIT(5)

struct sys_state {
	uint32_t state;
	uint32_t users;
	uint32_t keys;
};

void hexdump_ascii(const uint8_t *data, size_t len);

const char *taf_to_str(uint32_t cmd_id);

#endif
