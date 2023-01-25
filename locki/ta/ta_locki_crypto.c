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
#include <string.h>

#include <tee_api_defines.h>
#include <tee_internal_api.h>
#include <utee_defines.h>

#include <ta_locki_crypto.h>

void free_crypto_context(struct crypto_context *ctx)
{
	if (!ctx) {
		EMSG("Trying to free crypto context on an invalid pointer!");
		return;
	}

	if (ctx->handle != TEE_HANDLE_NULL) {
		TEE_FreeOperation(ctx->handle);
		ctx->handle = TEE_HANDLE_NULL;
	}
}


TEE_Result sha256_init(struct crypto_context *ctx)
{
	if (!ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	return TEE_AllocateOperation(&ctx->handle, TEE_ALG_SHA256,
				     TEE_MODE_DIGEST, 0);
}

TEE_Result sha256_update(struct crypto_context *ctx,
			 const uint8_t *in, const size_t inlen)
{
	if (!ctx || !in || inlen == 0) {
		DMSG("ctx is: %s NULL", ctx ? "NOT" : "");
		DMSG("in is: %s NULL", in ? "NOT" : "");
		DMSG("inlen is: %lu", inlen);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	TEE_DigestUpdate(ctx->handle, in, inlen);

	return TEE_SUCCESS;
}

TEE_Result sha256_final(struct crypto_context *ctx,
			const uint8_t *in, const size_t inlen,
			uint8_t *digest)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	uint32_t hash_len = TEE_SHA256_HASH_SIZE;

	if (!ctx || !digest) {
		DMSG("ctx is: %s NULL", ctx ? "NOT" : "");
		DMSG("digest is: %s NULL", digest ? "NOT" : "");
		goto err;
	}

	/* Clear whatever could have been left in the buffer */
	memset(digest, 0, hash_len);
	if (in && inlen > 0)
		res = TEE_DigestDoFinal(ctx->handle, in, inlen, digest, &hash_len);
	else
		res = TEE_DigestDoFinal(ctx->handle, NULL, 0, digest, &hash_len);
err:
	free_crypto_context(ctx);

	return res;
}

/*
 * To verify:
 *   https://www.liavaag.org/English/SHA-Generator/
 *   https://emn178.github.io/online-tools/sha256.html
 */
TEE_Result sha256(const uint8_t *in, const size_t inlen, uint8_t *digest)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	struct crypto_context ctx = { 0 };

	if (!in || inlen == 0 || !digest)
		goto err;

	res = sha256_init(&ctx);
	if (res != TEE_SUCCESS)
		goto err;

	res = sha256_final(&ctx, in, inlen, digest);
err:
	free_crypto_context(&ctx);

	return res;
}

/*
 * To verify:
 *   https://www.liavaag.org/English/SHA-Generator/HMAC/
 */
TEE_Result hmac_sha256(const uint8_t *key, const size_t keylen,
		       const uint8_t *in, const size_t inlen,
		       uint8_t *out, uint32_t *outlen)
{
	TEE_Attribute attr = { 0 };
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
	TEE_Result res = TEE_SUCCESS;

	if (!key || !in || !out || !outlen)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * The GP HMAC functions will output just zeroes if the provided outlen
	 * is less than the TEE_SHA256_HASH_SIZE. Add this check to notice
	 * if/when that happens.
	 */
	if (*outlen < TEE_SHA256_HASH_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	/* This wants key length in bits. */
	res = TEE_AllocateOperation(&op_handle, TEE_ALG_HMAC_SHA256,
				    TEE_MODE_MAC, keylen * 8);
	if (res != TEE_SUCCESS) {
		EMSG("0x%08x", res);
		goto exit;
	}

	/* This wants key length in bits. */
	res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256, keylen * 8,
					  &key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("0x%08x", res);
		goto exit;
	}

	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, keylen);

	res = TEE_PopulateTransientObject(key_handle, &attr, 1);
	if (res != TEE_SUCCESS) {
		EMSG("0x%08x", res);
		goto exit;
	}

	res = TEE_SetOperationKey(op_handle, key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("0x%08x", res);
		goto exit;
	}

	TEE_MACInit(op_handle, NULL, 0);
	TEE_MACUpdate(op_handle, in, inlen);
	res = TEE_MACComputeFinal(op_handle, NULL, 0, out, outlen);
exit:
	if (op_handle != TEE_HANDLE_NULL) {
		TEE_FreeOperation(op_handle);
		op_handle = TEE_HANDLE_NULL;
	}

	TEE_FreeTransientObject(key_handle);

	return res;
}
