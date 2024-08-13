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
#ifndef _TA_LOCKI_KEYS_H
#define _TA_LOCKI_KEYS_H

#include <stdint.h>
#include <sys/queue.h>

#include <tee_api_types.h>
#include "utee_defines.h"

struct key {
	uint8_t id[TEE_SHA256_HASH_SIZE];
	uint8_t value[TEE_SHA256_HASH_SIZE];
	uint32_t handle;
	uint32_t attributes;
	TAILQ_ENTRY(key) entry;
};

void add_key(const char *key, const uint32_t key_size,
	     const char *identifier, const uint32_t identifier_size);

TEE_Result generate_key(uint8_t *username, size_t username_len,
			uint8_t *password, size_t password_len,
			uint8_t *reg, size_t reg_len,
			uint32_t key_handle, uint32_t attributes);
#endif
