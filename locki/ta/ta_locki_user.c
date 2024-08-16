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

#include <tee_internal_api.h>

#include <ta_locki_crypto.h>
#include <ta_locki_user.h>
#include <ta_locki_utils.h>
#include <common.h>

TAILQ_HEAD(user_list, user) user_list = TAILQ_HEAD_INITIALIZER(user_list);

static bool is_salt_set(struct user *user)
{
	uint8_t nbr_zeros = 0;
	for (size_t i = 0; i < sizeof(user->salt); i++) {
		if (user->salt[i] == 0)
			nbr_zeros++;
	}

	return nbr_zeros == sizeof(user->salt) ? false : true;
}

static TEE_Result create_password_digest(struct user *user, uint8_t *password,
					 size_t password_len, uint8_t *salt,
					 size_t salt_len)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct crypto_context ctx = { 0 };
	uint8_t ta_unique_key[TEE_SHA256_HASH_SIZE] = { 0 };

	if (!user || !password || password_len == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	res = sha256_init(&ctx);
	if (res != TEE_SUCCESS)
		goto err;

	res = sha256_update(&ctx, password, password_len);
	if (res != TEE_SUCCESS)
		goto err;

	if (user->flags & USER_SALT_PASSWORD) {
		if (!is_salt_set(user)) {
			DMSG("Salt is not set");
			if (salt) {
				// Use the provided salt by the client.
				DMSG("Using user provided salt");
				memcpy(user->salt, salt, salt_len);
				user->salt_len = salt_len;
			} else {
				DMSG("Generate random salt");
				get_random_nbr(user->salt, TEE_SHA256_HASH_SIZE);
				user->salt_len = TEE_SHA256_HASH_SIZE;
			}
		}
		res = sha256_update(&ctx, user->salt, user->salt_len);
		if (res != TEE_SUCCESS)
			goto err;
	}

	if (user->flags & USER_TA_UNIQUE_PASSWORD) {
		if (user->flags & USER_SALT_PASSWORD) {
			res = get_ta_unique_key(ta_unique_key,
						sizeof(ta_unique_key),
						user->salt, user->salt_len);
		} else {
			res = get_ta_unique_key(ta_unique_key,
						sizeof(ta_unique_key), NULL, 0);
		}

		if (res != TEE_SUCCESS)
			goto err;

		res = sha256_update(&ctx, ta_unique_key, sizeof(ta_unique_key));
		if (res != TEE_SUCCESS)
			goto err;
	}

	/* FIXME: Check whether to use HUK / TA unique key */
	res = sha256_final(&ctx, NULL, 0, user->password);
	if (res != TEE_SUCCESS)
		goto err;

	user->password_len = TEE_SHA256_HASH_SIZE;
err:
	if (res != TEE_SUCCESS) {
		free_crypto_context(&ctx);
		memset(user->salt, 0, sizeof(user->salt));
		memset(user->password, 0, sizeof(user->password));
	}
	return res;
}


static bool password_is_correct(struct user *user, uint8_t *password,
				size_t password_len)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	/*
	 * Create a temporary user, where we will try to re-create the same
	 * derived password as originally done when creating the user.
	 */
	struct user tmp_user = { 0 };

	/* Need to copy the flags from the user we're trying to verify. */
	tmp_user.flags = user->flags;

	/*
	 * The salt is not provided and shouldn't have to be provided, we simply
	 * use the saved one from the user we're trying to authenticate. We
	 * could also copy these fields to the tmp_user, but that's just un
	 * unnecessary operation.
	 */
	res = create_password_digest(&tmp_user, password, password_len,
				     user->salt, user->salt_len);
	if (res != TEE_SUCCESS)
		return false;

	/*
	 * The newly derived password should be the same as the saved one.
	 *
	 * Note, to avoid timing attacks, this has to be constant time
	 * comparison which TEE_MemCompare is.
	 */
	if (TEE_MemCompare(user->password, tmp_user.password,
			   user->password_len))
		return false;

	return true;
}


struct user* find_user(uint8_t *username, size_t username_len)
{
	struct user *user = NULL;

	TAILQ_FOREACH(user, &user_list, entry) {
		if (TEE_MemCompare(user->name, username, username_len) == 0) {
			DMSG("Found user: %s", (char *)username);
			return user;
		}
	}
	DMSG("Didn't find user %s (%lu)", (char *)username, username_len);
	return user;
}

struct user* find_and_validate_user(uint8_t *username, size_t username_len,
				    uint8_t *password, size_t password_len)
{
	struct user *user = NULL;

	user = find_user(username, username_len);
	if (!user)
		return NULL;

	if (user->flags & USER_UNAUTHENTICATED_MEASURE)
		goto success;

	if (!password_is_correct(user, password, password_len))
		return NULL;
success:
	DMSG("Found a valid user");
	return user;
}

static TEE_Result add_user(struct user_params *up)
{
	struct user *user = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	user = TEE_Malloc(sizeof(struct user), 0);
	if (!user)
		return TEE_ERROR_OUT_OF_MEMORY;

	memcpy(user->name, up->uinfo.id, up->uinfo.len);
	user->name_len = up->uinfo.len;
	user->flags = up->flags;

        res = create_password_digest(user,
				     up->ucreds.password,
                                     up->ucreds.password_len,
				     up->ucreds.salt,
				     up->ucreds.salt_len);
        if (res != TEE_SUCCESS)
		goto err;

	/* Add the user to the users list */
	TAILQ_INSERT_TAIL(&user_list, user, entry);
	DMSG("User '%s' has been added", (char *)user->name);
	goto success;
err:
	TEE_Free(user);
success:
	return res;
}

TEE_Result create_user(struct user_params *up)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	struct user *user = NULL;

	/*
	 * FIXME: Perhaps allow empty password and generate a random password
	 * for the user.
	 */
	if (!up->uinfo.id || up->uinfo.len == 0 || up->uinfo.len > 32)
		return res;

	if (up->ucreds.password && up->ucreds.password_len == 0)
		return res;

	/* FIXME: autogenerate password when none is provided */

	/* Add user if not already existing */
	user = find_user(up->uinfo.id, up->uinfo.len);
	if (user) {
		res = TEE_ERROR_GENERIC;
		goto err;
	}

	res = add_user(up);
err:
	return res;
}

uint32_t nbr_of_users(void)
{
	struct user *user = NULL;

	uint32_t users = 0;
	TAILQ_FOREACH(user, &user_list, entry) {
		users += 1;
	}
	return users;
}
