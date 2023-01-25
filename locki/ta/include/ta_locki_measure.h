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
#ifndef _LOCKI_MEASURE_H
#define _LOCKI_MEASURE_H

#include <stdint.h>
#include <sys/queue.h>

#include <tee_api_types.h>

#include <utee_defines.h>

struct reg_element {
	uint8_t id[TEE_SHA256_HASH_SIZE];
	uint32_t len;
	uint8_t val[TEE_SHA256_HASH_SIZE];
	TAILQ_ENTRY(reg_element) entry;
};

TEE_Result extend_register(struct reg_element *re, uint8_t *data,
			   size_t data_size);

struct reg_element* find_reg_element(uint8_t *id);

TEE_Result measure(uint8_t *username, size_t username_len,
		   uint8_t *password, size_t password_len,
		   uint8_t *reg, size_t reg_len,
		   uint8_t *data, size_t data_size);

TEE_Result get_measure(uint8_t *username, size_t username_len,
		       uint8_t *password __maybe_unused,
		       size_t password_len __maybe_unused,
		       uint8_t *reg, size_t reg_len,
		       uint8_t *digest, uint32_t *digest_size);

#endif
