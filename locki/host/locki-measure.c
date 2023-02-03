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
#include "sys/user.h"
#include <argp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <locki.h>
#include <locki-tool.h>

extern const char *argp_program_version;
extern const char *argp_program_bug_address;

static char doc[] = "'locki measure', is used to make measurements.";
static char args_doc[] = "ARG1 ARG2";
static bool verbose;

static struct argp_option options[] = {
	{ "data",      'd', "DATA",      0,  "Data to measure" },
	{ "get",       'g', 0,           0,  "Read out a measured value" },
	{ "password",  'p', "VALUE",     0,  "Authentication password" },
	{ "reg",       'r', "ID",        0,  "Register ID" },
	{ "sign",      's', 0,           0,  "Get the signature for the measurement" },
	{ "user",      'u', "USERNAME",  0,  "The name of the user" },
	{ "verbose",   'v', 0,           0,  "Verbose output" },
	{ 0 }
};

struct arguments {
	char *username;
	char *password;
	char *reg;
	char *data;
	bool get;
	bool sign;
	bool verbose;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct arguments *arguments =
		(struct arguments *)state->input;

	switch (key) {
	case 'd':
		arguments->data = arg;
		break;
	case 'g':
		arguments->get = true;
		break;
	case 'p':
		arguments->password = arg;
		break;
	case 'r':
		arguments->reg = arg;
		break;
	case 's':
		arguments->sign = true;
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

void print_digest(uint8_t *data, size_t len)
{
	size_t i = 0;
	for (i = 0; i < len; i++)
		printf("%02X", (char)data[i]);
	printf("\n");
}

int measure_main(int argc, char *argv[])
{
	int res = -1;
	struct arguments arg;
	uint8_t digest[32] = { 0 };

	arg.username = NULL;
	arg.password = NULL;
	arg.reg = NULL;
	arg.data = NULL;
	arg.get = false;
	arg.sign = false;
	arg.verbose = false;

	argp_parse(&argp, argc, argv, 0, 0, &arg);

	verbose = arg.verbose;

	if (arg.username) {
		/* Getting a measurement */
		if (arg.get && arg.reg) {
			if (arg.password) {
				/* Authenticated */
				printf("TODO: add requirement to authentic to get a measurement.\n");
				printf("      Running this is an un-authenticated for now.\n");
			}

			/* Unauthenticated */
			if (arg.sign) {
				printf("Getting the signature of a measurement\n");
				res = get_signed_measure(arg.username, strlen(arg.username),
							 NULL, 0,
							 (uint8_t *)arg.reg, strlen(arg.reg),
							 digest);
			} else {
				printf("Getting an un-authenticated measurement\n");
				res = get_measure(arg.username, strlen(arg.username),
						  NULL, 0,
						  (uint8_t *)arg.reg, strlen(arg.reg),
						  digest);
			}
			if (res)
				goto err;

			print_digest(digest, sizeof(digest));
			goto err;
		}

		/* Adding a measurement */
		if (arg.reg && arg.data)
		{
			if (arg.password) {
				printf("Do authenticated measure\n");
				res = measure(arg.username, strlen(arg.username),
					      arg.password, strlen(arg.password),
					      (uint8_t *)arg.reg, strlen(arg.reg),
					      (uint8_t *)arg.data, strlen(arg.data));
			} else {
				printf("Do un-authenticated measure\n");
				res = measure(arg.username, strlen(arg.username),
					      NULL, 0,
					      (uint8_t *)arg.reg, strlen(arg.reg),
					      (uint8_t *)arg.data, strlen(arg.data));
			}
			if (res)
				goto err;

			printf("Measured user: %s register: %s\n", arg.username, arg.reg);
		}
	}
err:
	if (res)
		printf("Failed running the command (%d)\n", res);
	return res;
}
