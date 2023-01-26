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
#include <ctype.h>
#include <stdint.h>
#include <string.h>
#include <sys/queue.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <tee_api_defines.h>
#include <utee_defines.h>

#include <common.h>
#include <ta_locki.h>
#include <ta_locki_crypto.h>
#include <ta_locki_debug.h>
#include <ta_locki_keys.h>
#include <ta_locki_measure.h>
#include <ta_locki_user.h>
#include <ta_locki_utils.h>

#define DEBUG

static struct sys_state sys_state;

extern TAILQ_HEAD(reg_list, reg_element) reg_list;
extern TAILQ_HEAD(user_list, user) user_list;
extern TAILQ_HEAD(key_list, key) key_list;

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
 * TA core functionality
 ******************************************************************************/
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

static TEE_Result status(uint32_t *state, uint32_t *users, uint32_t *keys)
{
	*users = nbr_of_users();
	*state = sys_state.state;
	*keys = sys_state.keys;
	return TEE_SUCCESS;
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
static TEE_Result ta_debug_dump_users(uint32_t param_types __maybe_unused,
				      TEE_Param params[4] __maybe_unused)
{
	DMSG("[[[ TA_LOCKI_CMD_DEBUG_DUMP_USERS ]]]");
	dump_user_list();
	return TEE_SUCCESS;
}

static TEE_Result ta_debug_dump_registers(uint32_t param_types __maybe_unused,
					  TEE_Param params[4] __maybe_unused)
{
	DMSG("[[[ TA_LOCKI_CMD_DEBUG_DUMP_REGISTERS ]]]");
	dump_reg_list();
	return TEE_SUCCESS;
}

/*******************************************************************************
 * Main entrance point for the various TA functions.
 ******************************************************************************/
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
