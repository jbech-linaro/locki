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

#include <ctype.h>
#include <err.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include <common.h>
#include <locki.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <locki_ta.h>

// #define DEBUG

TEEC_UUID uuid = LOCKI_TA_UUID;

/* Return codes */
enum {
	SUCCESS,
	ERROR,
};

/* Init session related */
static bool init_session_initialized;
static TEEC_Session teec_init_session;
static TEEC_Context ctx;

struct tee_data {
	TEEC_Operation operation;
	TEEC_Session session;
};

/* Shared tee data state between various calls. */
static struct tee_data td = { 0 };

/*******************************************************************************
 * Utility functions
 ******************************************************************************/
static int store_key_to_file(const char *filename, uint8_t *data, size_t len)
{
	int res = ERROR;
	FILE *fp = fopen(filename, "wb");
	if (!fp)
		return ERROR;

	res = fwrite(data, 1, len, fp);
	fclose(fp);
	return res;
}

int load_key_from_file(const char *filename, uint8_t **data, size_t *len)
{
	int res = ERROR;
	size_t ret = -1;
	FILE *fp = fopen(filename, "rb");

	if (!fp) {
		printf("fopen(%s) failed\n", filename);
		return res;
	}

	fseek(fp, 0, SEEK_END);
	*len = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	printf("Length of '%s' is: %lu\n", filename, *len);

	*data = malloc(*len);

	if (!data)
		goto err;

	ret = fread(*data, 1, *len, fp);
	if (ret != *len)
		free(*data);
	res = SUCCESS;
err:
	fclose(fp);
	return res;
}

/*******************************************************************************
 * TEE communication functions
 ******************************************************************************/
static bool init_session_exists(void)
{
	return init_session_initialized;
}

static TEEC_Result create_init_session(void)
{
	TEEC_Operation op = { 0 };
	TEEC_Result res = TEEC_ERROR_GENERIC;
	uint32_t err_origin = 0;

        op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);

	res = TEEC_OpenSession(&ctx, &teec_init_session, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		goto err;

	init_session_initialized = true;
err:
	return res;
}

/*
 * Initialize and open a session with the Locki TA running in the TEE.
 */
int initialize(void)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	uint32_t err_origin = 0;

	if (init_session_exists())
		return 0;

	memset(&td.operation, 0, sizeof(td.operation));

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	create_init_session();
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x\n",
		     res, err_origin);

	return res == TEEC_SUCCESS ? SUCCESS : ERROR;
}

static int open_session(void)
{
	uint32_t err_origin = 0;
	TEEC_Result res = TEEC_ERROR_GENERIC;

	initialize();

	res = TEEC_OpenSession(&ctx, &td.session, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		goto err;
err:
	return res == TEEC_SUCCESS ? SUCCESS : ERROR;
}

static void close_session(void)
{
	if (&td.session)
		TEEC_CloseSession(&td.session);
	memset(&td.session, 0, sizeof(td.session));
}

/*
 * Close the session and finalize the context for the init session. This
 * basically kills the running TA. int terminate(void). Note that this shouldn't
 * be used when running this as keep alive TA. But it is convenient when doing
 * development and debugging to have this.
 */
int terminate(void)
{
	if (init_session_exists()) {
		TEEC_CloseSession(&teec_init_session);
		init_session_initialized = false;
	}

	TEEC_FinalizeContext(&ctx);
	return 0;
}

/*
 * Run a command within the Locki TA.
 */
static int teec_invoke(uint32_t taf_id)
{
	const char *str __attribute__((unused)) = NULL;
	TEEC_Result res = TEEC_ERROR_GENERIC;
	uint32_t err_origin = TEEC_ORIGIN_API;

	res = TEEC_InvokeCommand(&td.session, taf_id, &td.operation,
				 &err_origin);

	if (res != TEEC_SUCCESS) {
		str = taf_to_str(taf_id);
		fprintf(stderr, "TEEC_InvokeCommand (%s) failed with code "
			"0x%x origin 0x%x\n", str, res, err_origin);
	}

	return res == TEEC_SUCCESS ? SUCCESS : ERROR;
}

/*******************************************************************************
 * TA functions
 ******************************************************************************/
int add_key(char *identity, char *key, uint8_t *data, size_t len)
{
	int res = ERROR;
	/* Both cannot be provided nor missing */
	if ((key && data) || (!key && !data))
		return res;

	res = open_session();
	if (res)
		goto err;

	td.operation.params[0].tmpref.buffer = identity;
	td.operation.params[0].tmpref.size = strlen(identity);
	if (key)
		td.operation.params[1].tmpref.buffer = key;
	else if (data)
		td.operation.params[1].tmpref.buffer = data;
	td.operation.params[1].tmpref.size = len;
	printf("identity size: %08lu\n", td.operation.params[0].tmpref.size);
	printf("key size: %08lu\n", td.operation.params[1].tmpref.size);
	td.operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT,
						   TEEC_MEMREF_TEMP_INOUT,
						   TEEC_NONE, TEEC_NONE);
	printf("Adding key: %s for identity: %s\n", key, identity);
	res = teec_invoke(TA_LOCKI_CMD_ADD_KEY);
err:
	close_session();

	return res;
}

/*
 * FIXME: Add algo and also add an identity
 */
int create_key(void)
{
	int res = ERROR;
	size_t key_size = MAX_KEY_SIZE;
	uint32_t key[MAX_KEY_SIZE] = { 0 };

	res = initialize();
	if (res) {
		/*
		 * If TEEC_InitializeContext fails, the program will quit and
		 * we won't end up here, so it's safe and we have to jump to
		 * the finalize here.
		 */
		goto err;
	}

	td.operation.params[0].tmpref.buffer = key;
	td.operation.params[0].tmpref.size = key_size;
	td.operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT,
						   TEEC_NONE, TEEC_NONE,
						   TEEC_NONE);
	res = teec_invoke(TA_LOCKI_CMD_CREATE_KEY);
	if (res != 0)
		goto err;

	key_size = td.operation.params[0].tmpref.size;
	res = store_key_to_file("key.bin", (uint8_t *)key, key_size);
	if (res != 0)
		goto err;

	hexdump_ascii((uint8_t *)key, key_size);
err:
	close_session();

	return res;
}

int reset(char *password, size_t len)
{
	int res = ERROR;
	res = open_session();
	if (res)
		goto err;

	td.operation.params[0].tmpref.buffer = password;
	td.operation.params[0].tmpref.size = len;
	td.operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT,
						   TEEC_NONE, TEEC_NONE,
						   TEEC_NONE);
	res = teec_invoke(TA_LOCKI_CMD_RESET);
err:
	close_session();
	return res;
}

int configure(char *password, size_t len)
{
	int res = ERROR;

	if (!password || len == 0)
		return res;

	res = open_session();
	if (res)
		goto err;

	td.operation.params[0].tmpref.buffer = password;
	td.operation.params[0].tmpref.size = len;
	td.operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT,
						   TEEC_NONE, TEEC_NONE,
						   TEEC_NONE);
	res = teec_invoke(TA_LOCKI_CMD_CONFIGURE);
err:
	close_session();
	return res;
}

int status(struct sys_state *st)
{
	int res = ERROR;
	if (!st)
		return res;

	res = open_session();
	if (res)
		goto err;

	td.operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT,
						   TEEC_VALUE_OUTPUT,
						   TEEC_VALUE_OUTPUT,
						   TEEC_NONE);
	res = teec_invoke(TA_LOCKI_CMD_STATUS);
	if (res)
		goto err;

	st->state = td.operation.params[0].value.a;
	st->users = td.operation.params[1].value.a;
	st->keys = td.operation.params[2].value.a;
err:
	close_session();

	return res;
}

int measure(char *username, size_t username_len,
	    char *password, size_t password_len,
	    uint8_t *reg, size_t reg_len,
	    uint8_t *data, size_t data_size) {
        int res = ERROR;

	/* FIXME: allow non-user / non-password measurements */
	if (!username || username_len == 0 ||
	    !reg || reg_len == 0 ||
	    !data || data_size == 0)
		return res;

	res = open_session();
	if (res)
		goto err;

	td.operation.params[0].tmpref.buffer = username;
	td.operation.params[0].tmpref.size = username_len;
	td.operation.params[1].tmpref.buffer = password;
	td.operation.params[1].tmpref.size = password_len;
	td.operation.params[2].tmpref.buffer = reg;
	td.operation.params[2].tmpref.size = reg_len;
	td.operation.params[3].tmpref.buffer = data;
	td.operation.params[3].tmpref.size = data_size;
        td.operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						   TEEC_MEMREF_TEMP_INPUT,
						   TEEC_MEMREF_TEMP_INPUT,
						   TEEC_MEMREF_TEMP_INPUT);
        res = teec_invoke(TA_LOCKI_CMD_MEASURE);
	if (res)
		goto err;
err:
	close_session();

	return res;
}

int get_measure(char *username, size_t username_len,
		char *password, size_t password_len,
		uint8_t *reg, size_t reg_len, uint8_t *digest)
{
        int res = ERROR;
	if (!username || username_len == 0 || !digest)
		return res;

	res = open_session();
	if (res)
		goto err;

	td.operation.params[0].tmpref.buffer = username;
	td.operation.params[0].tmpref.size = username_len;
	td.operation.params[1].tmpref.buffer = password;
	td.operation.params[1].tmpref.size = password_len;
	td.operation.params[2].tmpref.buffer = reg;
	td.operation.params[2].tmpref.size = reg_len;
	td.operation.params[3].tmpref.buffer = digest;
	td.operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						   TEEC_MEMREF_TEMP_INPUT,
						   TEEC_MEMREF_TEMP_INPUT,
						   TEEC_MEMREF_TEMP_OUTPUT);
	res = teec_invoke(TA_LOCKI_CMD_GET_MEASURE);
	if (res)
		goto err;
err:
	close_session();

	return res;
}

int create_user(char *username, size_t username_len,
		char *password, size_t password_len,
		uint8_t *salt, size_t salt_len,
		uint32_t flags)
{
	int res = ERROR;

	if (!username || username_len == 0)
		return res;

	if (password && password_len == 0)
		return res;

	res = open_session();
	if (res)
		goto err;

	td.operation.params[0].tmpref.buffer = username;
	td.operation.params[0].tmpref.size = username_len;
	td.operation.params[1].tmpref.buffer = password;
	td.operation.params[1].tmpref.size = password_len;
	td.operation.params[2].tmpref.buffer = salt;
	td.operation.params[2].tmpref.size = salt_len;
	td.operation.params[3].value.a = flags;
	td.operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT,
						   TEEC_MEMREF_TEMP_INOUT,
						   TEEC_MEMREF_TEMP_INPUT,
						   TEEC_VALUE_INPUT);
	res = teec_invoke(TA_LOCKI_CMD_CREATE_USER);
	if (res)
		goto err;
err:
	close_session();
	
	return res;
}

/*
 * Debug functions.
 */
int debug_dump_users(void)
{
	int res = ERROR;

	res = open_session();
	if (res)
		goto err;

	td.operation.paramTypes = 0;
	res = teec_invoke(TA_LOCKI_CMD_DEBUG_DUMP_USERS);
	if (res)
		goto err;
err:
	close_session();

	return res;
}

int debug_dump_registers(void)
{
	int res = ERROR;

	res = open_session();
	if (res)
		goto err;

	td.operation.paramTypes = 0;
	res = teec_invoke(TA_LOCKI_CMD_DEBUG_DUMP_REGISTERS);
	if (res)
		goto err;
err:
	close_session();

	return res;
}
