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
#ifndef _LOCKI_CRYPTO_H
#define _LOCKI_CRYPTO_H

#include <stdint.h>

#include <tee_api_defines.h>
#include <tee_api_types.h>

struct crypto_context {
	TEE_OperationHandle handle;
};


void free_crypto_context(struct crypto_context *ctx);
TEE_Result sha256_init(struct crypto_context *ctx);

TEE_Result sha256_update(struct crypto_context *ctx,
			 const uint8_t *in, const size_t inlen);

TEE_Result sha256_final(struct crypto_context *ctx,
			const uint8_t *in, const size_t inlen,
			uint8_t *digest);

TEE_Result sha256(const uint8_t *in, const size_t inlen, uint8_t *digest);

TEE_Result hmac_sha256(const uint8_t *key, const size_t keylen,
		       const uint8_t *in, const size_t inlen,
		       uint8_t *out, size_t *outlen);

#endif
