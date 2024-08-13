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

#include <trace.h>
#include <tee_api_defines.h>
#include <tee_internal_api.h>

#include <common.h>
#include <ta_locki_crypto.h>
#include <ta_locki_measure.h>
#include <ta_locki_user.h>

/* Linked list for measurement */
TAILQ_HEAD(reg_list, reg_element) reg_list = TAILQ_HEAD_INITIALIZER(reg_list);

TEE_Result extend_register(struct reg_element *re, uint8_t *data,
			   size_t data_size)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	struct crypto_context ctx = {0};

	if (!re || !data || data_size == 0)
		goto err;

	res = sha256_init(&ctx);
	if (res != TEE_SUCCESS)
		goto err;

	res = sha256_update(&ctx, re->val, re->len);
	if (res != TEE_SUCCESS)
		goto err;

	res = sha256_final(&ctx, data, data_size, re->val);
	if (res != TEE_SUCCESS)
		goto err;
err:
	free_crypto_context(&ctx);
	return res;
}

struct reg_element* find_reg_element(uint8_t *id)
{
	struct reg_element *re = NULL;

	TAILQ_FOREACH(re, &reg_list, entry) {
		if (TEE_MemCompare(re->id, id, TEE_SHA256_HASH_SIZE) == 0) {
			DMSG("Found matching reg_element");
			return re;
		}
	}
	DMSG("Didn't find a matching reg_element");
	return re;
}

TEE_Result create_reg_id(struct user *user, uint8_t *reg, size_t reg_len,
			 uint8_t *digest)
{
        TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	struct crypto_context ctx = { 0 };

	if (!user || !reg || reg_len == 0)
		goto err;

	res = sha256_init(&ctx);
	if (res != TEE_SUCCESS)
		goto err;

	res = sha256_update(&ctx, user->name, user->name_len);
	if (res != TEE_SUCCESS)
		goto err;

	res = sha256_final(&ctx, reg, reg_len, digest);
err:
	free_crypto_context(&ctx);

	return res;
}

TEE_Result measure(uint8_t *username, size_t username_len,
		   uint8_t *password, size_t password_len,
		   uint8_t *reg, size_t reg_len,
		   uint8_t *data, size_t data_size)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t reg_id[TEE_SHA256_HASH_SIZE] = { 0 };
	struct reg_element *re = NULL;
	struct user *user = NULL;

	// 1. Find the user
	// 2. Check that the password is correct or needed
	user = find_and_validate_user(username, username_len, password, password_len);
	if (!user) {
		DMSG("Not allowed to make a measurement!");
		res = TEE_ERROR_GENERIC;
		goto err;
	}

	res = create_reg_id(user, reg, reg_len, reg_id);
	if (res != TEE_SUCCESS)
		goto err;

	re = find_reg_element(reg_id);
	if (!re) {
		DMSG("Register didn't exist! Creating one");
		re = TEE_Malloc(sizeof(struct reg_element), 0);
		if (!re) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto err;
		}
		memcpy(re->id, reg_id, TEE_SHA256_HASH_SIZE);
		/*
		 * FIXME: At some point the future, this should depend on the
		 * type of alg.
		 */
		re->len = TEE_SHA256_HASH_SIZE;
		TAILQ_INSERT_TAIL(&reg_list, re, entry);
	}

	// 5. Make sha256(current_hash || data) as measurement
	res = extend_register(re, data, data_size);
err:
	return res;
}

TEE_Result get_measure(uint8_t *username, size_t username_len,
		       uint8_t *password __maybe_unused,
		       size_t password_len __maybe_unused,
		       uint8_t *reg, size_t reg_len,
		       uint8_t *digest, size_t *digest_size,
		       uint32_t properties)
{
	struct user *user = NULL;
	struct reg_element *re = NULL;
	uint8_t target_reg[TEE_SHA256_HASH_SIZE];
	TEE_Result res = TEE_ERROR_GENERIC;

	user = find_user(username, username_len);
	if (!user)
		goto err;

	res = create_reg_id(user, reg, reg_len, target_reg);
	if (res != TEE_SUCCESS)
		goto err;

	re = find_reg_element(target_reg);
	if (!re) {
		res = TEE_ERROR_GENERIC;
		goto err;
	}

	*digest_size = TEE_SHA256_HASH_SIZE;
	if (IS_SET(properties, SIGNED_MEASUREMENT)) {
		hmac_sha256(user->password, user->password_len,
			    re->val, re->len,
			    digest, digest_size);
	} else {
		memcpy(digest, re->val, TEE_SHA256_HASH_SIZE);
	}
err:
	return res;
}
