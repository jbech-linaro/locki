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

#include <trace.h>

#include <common.h>
#include <ta_locki_keys.h>
#include <ta_locki_utils.h>

TAILQ_HEAD(key_list, key) key_list = TAILQ_HEAD_INITIALIZER(key_list);

void add_key(const char *key, const uint32_t *key_size,
	     const char *identifier, const uint32_t *identifier_size)
{
	DMSG("Got identifier: '%s' (%u)", identifier, *identifier_size);
	DMSG("Got identifier: '%s' (%u)", key, *key_size);
}

TEE_Result create_key(uint8_t *key, uint32_t *key_size)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!key || !key_size)
		return TEE_ERROR_BAD_PARAMETERS;

	if (*key_size > MAX_KEY_SIZE )
		return TEE_ERROR_SHORT_BUFFER;

	res = get_random_nbr(key, *key_size);
	DMSG("Created key:");
	hexdump_ascii((uint8_t *)key, *key_size);

	return res;
}
