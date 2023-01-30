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
#include <stdint.h>

#include <tee_api_defines.h>
#include <tee_internal_api.h>
#include <trace.h>
#include <utee_defines.h>

#include <common.h>
#include <ta_locki_crypto.h>
#include <ta_locki_measure.h>
#include <ta_locki_keys.h>
#include <ta_locki_utils.h>
#include <ta_locki_user.h>

TAILQ_HEAD(key_list, key) key_list = TAILQ_HEAD_INITIALIZER(key_list);

static TEE_Result create_key_id(struct reg_element *re, struct key *key)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct crypto_context ctx = { 0 };

	DMSG("Create key id");

	if (!re || !key)
		goto err;

	res = sha256_init(&ctx);
	if (res != TEE_SUCCESS)
		goto err;

	res = sha256_update(&ctx, re->val, sizeof(re->val));
	if (res != TEE_SUCCESS)
		goto err;

        res = sha256_final(&ctx, (uint8_t *)&key->handle, sizeof(key->handle),
			   key->id);
err:
	free_crypto_context(&ctx);
	return res;
}

static bool key_exist(struct key *key)
{
	struct key *current = NULL;

	TAILQ_FOREACH(current, &key_list, entry) {
		if (TEE_MemCompare(current->id, key->id, sizeof(key->id)) == 0) {
			/*
			 * Note, the print below doesn't uniquely identity a key. The
			 * key->id should be printed to fully identify it.
			 */
			DMSG("Found key: %u", key->handle);
			return true;
		}
	}
	DMSG("Didn't find an existing key");
	return false;
}

void add_key(const char *key, const uint32_t *key_size,
	     const char *identifier, const uint32_t *identifier_size)
{
	DMSG("Got identifier: '%s' (%u)", identifier, *identifier_size);
	DMSG("Got identifier: '%s' (%u)", key, *key_size);
}

TEE_Result generate_key(uint8_t *username, size_t username_len,
			uint8_t *password, size_t password_len,
			uint8_t *reg, size_t reg_len,
			uint32_t key_handle, uint32_t attributes __maybe_unused)
{
	struct user *user = NULL;
	struct reg_element *re = NULL;
	uint8_t target_reg[TEE_SHA256_HASH_SIZE] = { 0 };
	struct key *key = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	user = find_and_validate_user(username, username_len,
				      password, password_len);
	if (!user)
		return TEE_ERROR_GENERIC;
        /*
         * Get the current register element belonging to the user in question.
         */
        res = create_reg_id(user, reg, reg_len, target_reg);
	if (res != TEE_SUCCESS)
		return res;

	re = find_reg_element(target_reg);
	if (!re)
		return TEE_ERROR_GENERIC;

	/*
	 * With reg element, create a new index for the key
	 * ---> key id = hash(re.val || key_handle)
	 *
	 * Note here that re.val is derived from:
	 *  a) User name
	 *  b) Password
	 *  c) the register id
	 *
	 *  So on practice the key id comes from these three and the register
	 *  value and the key handle.
	 */
	key = TEE_Malloc(sizeof(struct key), 0);
	if (!key)
		return TEE_ERROR_OUT_OF_MEMORY;

	key->handle = key_handle;
	res = create_key_id(re, key);
	if (res != TEE_SUCCESS)
		goto err;

	DMSG("Key ID is:");
	hexdump_ascii(key->id, sizeof(key->id));

	if (res != TEE_SUCCESS)
		goto err;
	res = get_random_nbr(key->value, sizeof(key->value));
	DMSG("Created key:");
	hexdump_ascii(key->value, sizeof(key->value));

	/* Only add the key, if it is a new key */
	if (key_exist(key)) {
		DMSG("Key not created: key handle: %u for %s already exist",
		     key->handle, username);
		res = TEE_ERROR_GENERIC;
		goto err;
	}

	TAILQ_INSERT_TAIL(&key_list, key, entry);
	DMSG("Successfully created and stored a new key");
err:
	if (res != TEE_SUCCESS)
		TEE_Free(key);

	return res;
}
