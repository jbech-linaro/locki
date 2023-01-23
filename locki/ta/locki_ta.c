/*
 * Copyright (c) 2023, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "tee_api_types.h"
#include "trace.h"
#include <ctype.h>
#include <stdint.h>
#include <string.h>
#include <sys/queue.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <tee_api_defines.h>
#include <pta_system.h>
#include <utee_defines.h>

#include <common.h>
#include <locki_ta.h>

#define DEBUG

static struct sys_state sys_state;

struct reg_element {
	uint8_t id[TEE_SHA256_HASH_SIZE];
	uint32_t len;
	uint8_t val[TEE_SHA256_HASH_SIZE];
	TAILQ_ENTRY(reg_element) entry;
};

struct user {
	uint8_t name[32];
	uint8_t name_len;
	uint8_t password[TEE_SHA256_HASH_SIZE]; /* Run via Argon or PBKDF2? */
	uint8_t password_len;
	uint8_t salt[TEE_SHA256_HASH_SIZE];
	uint8_t salt_len;
	uint8_t flags;
	TAILQ_ENTRY(user) entry;
};

/* Linked list for all users */
TAILQ_HEAD(user_list, user) user_list = TAILQ_HEAD_INITIALIZER(user_list);

/* Linked list for measurement */
TAILQ_HEAD(reg_list, reg_element) reg_list = TAILQ_HEAD_INITIALIZER(reg_list);

struct crypto_context {
	TEE_OperationHandle handle;
};

enum system_state {
	STATE_UNINITIALIZED = 0,
	STATE_INITIALIZED,
	STATE_CONFIGURED,
};


/*******************************************************************************
 * TEE/TA setup and teardown functions.
 ******************************************************************************/

/*
 * Called when the instance of the TA is created. This is the first call in the
 * TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("Locki TA instance created");

	sys_state.state = STATE_UNINITIALIZED;
	sys_state.users = 0;
	sys_state.keys = 0;

	/* FIXME: Load state from persistent storage */

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not crashed or
 * panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	struct user *user_current = NULL;
	struct user *user_next = NULL;
	struct reg_element *reg_current = NULL;
	struct reg_element *reg_next = NULL;

	DMSG("Releasing user resources");
	TAILQ_FOREACH_SAFE(user_current, &user_list, entry, user_next) {
		TAILQ_REMOVE(&user_list, user_current, entry);
		memset(user_current, 0, sizeof(struct user));
		TEE_Free(user_current);
		user_current = NULL;
	}

	DMSG("Releasing register resources");
	TAILQ_FOREACH_SAFE(reg_current, &reg_list, entry, reg_next) {
		TAILQ_REMOVE(&reg_list, reg_current, entry);
		memset(reg_current, 0, sizeof(struct reg_element));
		TEE_Free(reg_current);
		reg_current = NULL;
	}
	/* FIXME: Save to disk if needed */
	DMSG("Locki TA instance destroyed");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated with
 * a value to be able to identify this session in subsequent calls to the TA.
 * In this function you will normally do the global initialization for the TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
				    TEE_Param __maybe_unused params[4],
				    void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("Locki TA has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was assigned
 * by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	DMSG("Locki TA session closed\n");
}

/*******************************************************************************
 * Utility functions
 ******************************************************************************/
static TEE_Result get_ta_unique_key(uint8_t *key, uint8_t key_size,
				    uint8_t *extra, uint16_t extra_size)
{
	static const TEE_UUID system_uuid = PTA_SYSTEM_UUID;
	TEE_TASessionHandle handle = TEE_HANDLE_NULL;
	uint32_t ret_origin = 0;
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_Param params[4] = { 0 };
	uint32_t param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					       TEE_PARAM_TYPE_MEMREF_OUTPUT,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE);
	if (!key)
		return TEE_ERROR_BAD_PARAMETERS;

        res = TEE_OpenTASession(&system_uuid, 0, 0, NULL, &handle, &ret_origin);
        if (res != TEE_SUCCESS)
		return TEE_ERROR_GENERIC;

	/* To provide salt for the generated key. */
	if (extra && extra_size > 0) {
		params[0].memref.buffer = extra;
		params[0].memref.size = extra_size;
	}

	params[1].memref.buffer = key;
	params[1].memref.size = key_size;
        res = TEE_InvokeTACommand(handle, 100, PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY,
                                  param_types, params, &ret_origin);

        TEE_CloseTASession(handle);

	return res;
}

static void free_crypto_context(struct crypto_context *ctx)
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


static TEE_Result sha256_init(struct crypto_context *ctx)
{
	if (!ctx)
		return TEE_ERROR_BAD_PARAMETERS;

        return TEE_AllocateOperation(&ctx->handle, TEE_ALG_SHA256,
                                     TEE_MODE_DIGEST, 0);
}

static TEE_Result sha256_update(struct crypto_context *ctx,
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

static TEE_Result sha256_final(struct crypto_context *ctx,
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
static TEE_Result sha256(const uint8_t *in, const size_t inlen, uint8_t *digest)
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
static TEE_Result hmac_sha256(const uint8_t *key, const size_t keylen,
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

static TEE_Result create_reg_id(struct user *user, uint8_t *reg, size_t reg_len,
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
	if (res != TEE_SUCCESS)
		goto err;
err:
	free_crypto_context(&ctx);
	return res;

	return res;
}

static TEE_Result extend_register(struct reg_element *re, uint8_t *data, size_t data_size)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	struct crypto_context ctx = { 0 };

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

#ifdef DEBUG
/*
 * This should NEVER EVER be enabled in a production build !!!
 */
static void dump_user(struct user *u)
{
	DMSG("<<<<<<< %s >>>>>>>", u->name);
	DMSG("  password:");
	hexdump_ascii(u->password, u->password_len);
	if (IS_SET(u->flags, USER_SALT_PASSWORD)) {
		DMSG("  salt:");
		hexdump_ascii(u->salt, u->salt_len);
	} else
		DMSG("  salt: NOT used");
	DMSG("--------------------------");
}
#else
static void dump_user(struct user *u) { (void)u }
#endif

#ifdef DEBUG
static void dump_user_list(void)
{
	struct user *user = NULL;
	size_t i = 0;
	TAILQ_FOREACH(user, &user_list, entry) {
		dump_user(user);
		i++;
	}
	DMSG("In total there are %lu user(s)", i);
}
#else
static void dump_user_list(void) {}
#endif

#ifdef DEBUG
static void dump_register(struct reg_element *re)
{
	DMSG("id:");
	hexdump_ascii(re->id, sizeof(re->id));
	DMSG("val");
	hexdump_ascii(re->val, sizeof(re->val));
}
#else
static void dump_register(struct reg_element *re) {}
#endif

#ifdef DEBUG
static void dump_reg_list(void)
{
	struct reg_element *re = NULL;
	size_t i = 0;
	TAILQ_FOREACH(re, &reg_list, entry) {
		dump_register(re);
		i++;
	}
	DMSG("In total there are %lu register(s)", i);
}
#else
static void dump_reg_list(void) {}
#endif

static TEE_Result get_random_nbr(uint8_t *nbr, uint32_t size)
{
	void *buf = NULL;
	if (!nbr)
		return TEE_ERROR_BAD_PARAMETERS;

	buf = TEE_Malloc(size, 0);
	if (!buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	DMSG("Generating random data over %u bytes.", size);
	TEE_GenerateRandom(buf, size);
	TEE_MemMove(nbr, buf, size);
	TEE_Free(buf);

	return TEE_SUCCESS;
}

static struct reg_element* find_reg_element(uint8_t *id)
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

static struct user* find_user(uint8_t *username, size_t username_len)
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
        if (TEE_MemCompare(user->password , tmp_user.password, user->password_len))
		return false;

	return true;
}

static struct user* find_and_validate_user(uint8_t *username, size_t username_len,
					   uint8_t *password, size_t password_len)
{
        struct user *user = NULL;

	user = find_user(username, username_len);
	if (!user)
		return NULL;

	if (user->flags & USER_UNAUTHENTICATED_MEASURE)
		return user;

	if (!password_is_correct(user, password, password_len))
		return NULL;

	DMSG("Found a valid user");
	return user;
}

/*******************************************************************************
 * TA core functionality
 ******************************************************************************/
static void add_key(const char *key, const uint32_t *key_size,
		    const char *identifier, const uint32_t *identifier_size)
{
	DMSG("Got identifier: '%s' (%u)", identifier, *identifier_size);
	DMSG("Got identifier: '%s' (%u)", key, *key_size);
}

static TEE_Result create_key(uint8_t *key, uint32_t *key_size)
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

static TEE_Result reset(const char *password, uint32_t len)
{
	(void)password;
	(void)len;
	/* 1. Retrieve a stored password */

	/* 2. Compare it with the provided password */

	/* 3a. Match --> reset */
	/* 3b. No Match --> error */
	return TEE_SUCCESS;
}

static TEE_Result configure(const char *password, uint32_t len)
{
	(void)password;
	(void)len;
	/* 1. Setup initial data structures */

	/* 2. Store the provided password as the master config key */

	return TEE_SUCCESS;
}

static uint32_t nbr_of_users(void)
{
	struct user *user = NULL;

	uint32_t users = 0;
	TAILQ_FOREACH(user, &user_list, entry) {
		users += 1;
	}
	return users;
}

static TEE_Result status(uint32_t *state, uint32_t *users, uint32_t *keys)
{
	*users = nbr_of_users();
	*state = sys_state.state;
	*keys = sys_state.keys;
	return TEE_SUCCESS;
}

static TEE_Result measure(uint8_t *username, size_t username_len,
			  uint8_t *password, size_t password_len,
                          uint8_t *reg, size_t reg_len,
			  uint8_t *data, size_t data_size)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t reg_id[TEE_SHA256_HASH_SIZE] = { 0 };
	struct reg_element tmp_re = { 0 };
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

static TEE_Result get_measure(uint8_t *username, size_t username_len,
			      uint8_t *password, size_t password_len,
			      uint8_t *reg, size_t reg_len,
			      uint8_t *digest, uint32_t *digest_size)
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
	
	memcpy(digest, re->val, TEE_SHA256_HASH_SIZE);
	*digest_size = TEE_SHA256_HASH_SIZE;
err:
	return res;
}

static TEE_Result add_user(uint8_t *username, uint32_t username_len,
			   uint8_t *password, uint32_t password_len,
			   uint8_t *salt, uint32_t salt_len,
			   uint32_t flags)
{
	struct user *user = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	user = TEE_Malloc(sizeof(struct user), 0);
	if (!user)
		return TEE_ERROR_OUT_OF_MEMORY;

	memcpy(user->name, username, username_len);
	user->name_len = username_len;
	user->flags = flags;

	res = create_password_digest(user, password, password_len, salt, salt_len);
	if (res != TEE_SUCCESS)
		goto err;

	/* Add the user to the users list */
	TAILQ_INSERT_TAIL(&user_list, user, entry);
	DMSG("User '%s' has been added", (char *)username);
	goto success;
err:
	if (user)
		TEE_Free(user);
success:
	return res;
}

static TEE_Result create_user(uint8_t *username, uint32_t username_len,
                              uint8_t *password, uint32_t password_len,
                              uint8_t *salt, uint32_t salt_len,
                              uint32_t flags)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	struct user *user = NULL;

        /*
         * FIXME: Perhaps allow empty password and generate a random password
         * for the user.
         */
        if (!username || username_len == 0 || username_len > 32)
		return res;

	if (password && password_len == 0)
		return res;

	/* FIXME: autogenerate password when none is provided */

	/* Add user if not already existing */
	user = find_user(username, username_len);
	if (user) {
		res = TEE_ERROR_GENERIC;
		goto err;
	}

        res = add_user(username, username_len, password, password_len, salt,
                       salt_len, flags);
err:
	return res;
}

/*******************************************************************************
 * TA parameter call check and conversion
 ******************************************************************************/
static TEE_Result ta_add_key(uint32_t param_types, TEE_Param params[4])
{
	const char *key = params[0].memref.buffer;
	const uint32_t *key_size = &params[0].memref.size;
	const char *identifier = params[1].memref.buffer;
	const uint32_t *identifier_size = &params[1].memref.size;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						   TEE_PARAM_TYPE_MEMREF_INOUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	DMSG("[[[ TA_LOCKI_CMD_ADD_KEY ]]]");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	add_key(key, key_size, identifier, identifier_size);

	return TEE_SUCCESS;
}

static TEE_Result ta_create_key(uint32_t param_types, TEE_Param params[4])
{
	uint8_t *key = params[0].memref.buffer;
	uint32_t *key_size = &params[0].memref.size;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	DMSG("[[[ TA_LOCKI_CMD_CREATE_KEY ]]]");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	return create_key(key, key_size);
}

static TEE_Result ta_reset(uint32_t param_types, TEE_Param params[4])
{
	uint32_t *password = params[0].memref.buffer;
	uint32_t len = params[0].memref.size;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	DMSG("[[[ TA_LOCKI_CMD_RESET ]]]");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	return reset((const char *)password, len);
}

static TEE_Result ta_configure(uint32_t param_types, TEE_Param params[4])
{
	uint32_t *password = params[0].memref.buffer;
	uint32_t len = params[0].memref.size;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	DMSG("[[[ TA_LOCKI_CMD_CONFIGURE ]]]");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	return configure((const char *)password, len);
}

static TEE_Result ta_status(uint32_t param_types, TEE_Param params[4])
{
	uint32_t *state = &params[0].value.a;
	uint32_t *users = &params[1].value.a;
	uint32_t *keys = &params[2].value.a;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
						   TEE_PARAM_TYPE_VALUE_OUTPUT,
						   TEE_PARAM_TYPE_VALUE_OUTPUT,
						   TEE_PARAM_TYPE_NONE);
	DMSG("[[[ TA_LOCKI_CMD_STATUS ]]]");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	return status(state, users, keys);
}

static TEE_Result ta_measure(uint32_t param_types, TEE_Param params[4])
{
	uint8_t *username = params[0].memref.buffer;
	size_t username_len = params[0].memref.size;
	uint8_t *password = params[1].memref.buffer;
	size_t password_len = params[1].memref.size;
	uint8_t *reg = params[2].memref.buffer;
	size_t reg_len = params[2].memref.size;
	uint8_t *data = params[3].memref.buffer;
	size_t data_size = params[3].memref.size;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT);
	DMSG("[[[ TA_LOCKI_CMD_MEASURE ]]]");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

        return measure(username, username_len, password, password_len, reg,
                       reg_len, data, data_size);
}

static TEE_Result ta_get_measure(uint32_t param_types, TEE_Param params[4])
{
	uint8_t *username = params[0].memref.buffer;
	size_t username_len = params[0].memref.size;
	uint8_t *password = params[1].memref.buffer;
	uint32_t password_len = params[1].memref.size;
	uint8_t *reg = params[2].memref.buffer;
	uint32_t reg_len = params[2].memref.size;
	uint8_t *digest = params[3].memref.buffer;
	uint32_t *digest_size = &params[3].memref.size;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT);
	DMSG("[[[ TA_LOCKI_CMD_GET_MEASURE ]]]");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	return get_measure(username, username_len, password, password_len, reg, reg_len, digest, digest_size);
}

static TEE_Result ta_create_user(uint32_t param_types, TEE_Param params[4])
{
	uint8_t *user = params[0].memref.buffer;
	uint32_t user_len = params[0].memref.size;
	uint8_t *password = params[1].memref.buffer;
	uint32_t password_len = params[1].memref.size;
	uint8_t *salt = params[2].memref.buffer;
	uint32_t salt_len = params[2].memref.size;
	uint32_t flags = params[3].value.a;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						   TEE_PARAM_TYPE_MEMREF_INOUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_VALUE_INPUT);
	DMSG("[[[ TA_LOCKI_CMD_CREATE_USER ]]]");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

        return create_user(user, user_len, password, password_len, salt,
                           salt_len, flags);
}


/*******************************************************************************
 * Debug functions
 ******************************************************************************/
static TEE_Result ta_debug_dump_users(uint32_t param_types, TEE_Param params[4])
{
	DMSG("[[[ TA_LOCKI_CMD_DEBUG_DUMP_USERS ]]]");
	dump_user_list();
	return TEE_SUCCESS;
}

static TEE_Result ta_debug_dump_registers(uint32_t param_types, TEE_Param params[4])
{
	DMSG("[[[ TA_LOCKI_CMD_DEBUG_DUMP_REGISTERS ]]]");
	dump_reg_list();
	return TEE_SUCCESS;
}


TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
				      uint32_t cmd_id, uint32_t param_types,
				      TEE_Param params[4])
{
	switch (cmd_id) {
	case TA_LOCKI_CMD_ADD_KEY:
		return ta_add_key(param_types, params);
	case TA_LOCKI_CMD_CREATE_KEY:
		return ta_create_key(param_types, params);
	case TA_LOCKI_CMD_RESET:
		return ta_reset(param_types, params);
	case TA_LOCKI_CMD_CONFIGURE:
		return ta_configure(param_types, params);
	case TA_LOCKI_CMD_STATUS:
		return ta_status(param_types, params);
	case TA_LOCKI_CMD_MEASURE:
		return ta_measure(param_types, params);
	case TA_LOCKI_CMD_GET_MEASURE:
		return ta_get_measure(param_types, params);
	case TA_LOCKI_CMD_CREATE_USER:
		return ta_create_user(param_types, params);

	case TA_LOCKI_CMD_DEBUG_DUMP_USERS:
		return ta_debug_dump_users(param_types, params);
	case TA_LOCKI_CMD_DEBUG_DUMP_REGISTERS:
		return ta_debug_dump_registers(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
