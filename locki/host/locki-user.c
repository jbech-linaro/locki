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

static char doc[] = "'locki user', is used to create and manage users.";
static char args_doc[] = "ARG1 ARG2";
static bool verbose;

static struct argp_option options[] = {
	{ "flags",     'f', "VALUE",     0,  "Flags to pass" },
	{ "password",  'p', "VALUE",     0,  "Authentication password" },
	{ "salt",      's', "VALUE",     0,  "The salt" },
	{ "user",      'u', "USERNAME",  0,  "The name of the user" },
	{ "verbose",   'v', 0,           0,  "Verbose output" },
	{ 0 }
};

struct arguments {
	char *username;
	uint8_t *salt;
	char *password;
	uint32_t flags;
	bool verbose;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct arguments *arguments =
		(struct arguments *)state->input;

	switch (key) {
	case 'f':
		arguments->flags = strtoul(arg, NULL, 16);
		break;
	case 's':
		arguments->salt = (uint8_t *)arg;
		break;
	case 'p':
		arguments->password = arg;
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

int user_main(int argc, char *argv[])
{
	int res = -1;
	struct arguments arg;

	arg.username = NULL;
	arg.salt = NULL;
	arg.password = NULL;
	arg.flags = 0;
	arg.verbose = false;

	argp_parse(&argp, argc, argv, 0, 0, &arg);

	verbose = arg.verbose;

	if (arg.username && arg.password) {
		printf("Creating user: %s\n", arg.username);
		if (arg.salt) {
			res = create_user(arg.username, strlen(arg.username),
					  arg.password, strlen(arg.password),
					  arg.salt, sizeof(arg.salt),
					  arg.flags);
		} else {
			res = create_user(arg.username, strlen(arg.username),
					  arg.password, strlen(arg.password),
					  NULL, 0,
					  arg.flags);
		}
	}

	return res;
}
