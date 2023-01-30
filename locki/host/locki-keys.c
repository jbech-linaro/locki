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
#include <argp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <locki.h>
#include <locki-tool.h>

extern const char *argp_program_version;
extern const char *argp_program_bug_address;

static char doc[] = "'locki keys', is used to create and manage keys.";
static char args_doc[] = "ARG1 ARG2";
static bool verbose;

static struct argp_option options[] = {
	{ "attributes", 'a', "VALUE",     0,  "Attributes to pass, as 32-bit hex string (ffddccbb)" },
	{ "key_handle", 'h', "VALUE",     0,  "Used to reference a certain key" },
	{ "password",   'p', "VALUE",     0,  "Authentication password" },
	{ "reg",        'r', "ID",        0,  "Register ID" },
	{ "user",       'u', "USERNAME",  0,  "The name of the user" },
	{ "verbose",    'v', 0,           0,  "Verbose output" },
	{ 0 }
};

struct arguments {
	uint32_t attributes;
	uint32_t key_handle;
	char *username;
	char *password;
	char *reg;
	bool verbose;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct arguments *arguments =
		(struct arguments *)state->input;

	switch (key) {
	case 'a':
		arguments->attributes = strtoul(arg, NULL, 16);
		break;
	case 'h':
		arguments->key_handle = strtoul(arg, NULL, 0);
		break;
	case 'p':
		arguments->password = arg;
		break;
	case 'r':
		arguments->reg = arg;
		break;
	case 'u':
		arguments->username = arg;
		break;
	case 'v':
		arguments->verbose = true;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static struct argp argp = {
	options,
	parse_opt,
	args_doc,
	doc
};

int key_main(int argc, char *argv[])
{
	bool args_ok = true;
	int res = -1;
	struct arguments arg;

	arg.attributes = 0;
	arg.key_handle = 0;
	arg.username = NULL;
	arg.password = NULL;
	arg.reg = NULL;
	arg.verbose = false;

	argp_parse(&argp, argc, argv, 0, 0, &arg);

	verbose = arg.verbose;

	if (!arg.username) {
		printf("Command '%s' requires a username\n", argv[0]);
		args_ok = false;
	}

	if (!arg.password) {
		printf("Command '%s' requires a password\n", argv[0]);
		args_ok = false;
	}

	if (!arg.reg) {
		printf("Command '%s' requires a register\n", argv[0]);
		args_ok = false;
	}

	if (arg.key_handle == 0) {
		printf("No key handle provided, use default (0)\n");
	}

	if (!args_ok)
		goto err;

	res = generate_key(arg.username, strlen(arg.username),
			   arg.password, strlen(arg.password),
			   (uint8_t *)arg.reg, strlen(arg.reg),
			   arg.key_handle, arg.attributes);
err:
	return res;
}
