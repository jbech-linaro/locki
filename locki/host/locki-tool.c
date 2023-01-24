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
#include <argp.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <common.h>
#include <locki.h>

static bool verbose;

/*******************************************************************************
 * Argument parser
 ******************************************************************************/
const char *argp_program_version = "Locki v0.1";
const char *argp_program_bug_address = "<joakim.bech@linaro.org>";

/*******************************************************************************
 * Help command
 ******************************************************************************/
int print_help(void)
{
	printf("Usage: myprogram [OPTION]...\n\n");
	printf("Options:\n");
	printf("  user        For user creation\n");
	printf("\n");

	return 0;
}

/*******************************************************************************
 * Subcommand: User
 ******************************************************************************/
static char doc_user[] = "'locki user', is used to create and manage users.";
static char args_doc[] = "ARG1 ARG2";

static struct argp_option options_user[] = {
	{ "flags",     'f', "VALUE",     0,  "Flags to pass" },
	{ "password",  'p', "VALUE",     0,  "Authentication password" },
	{ "salt",      's', "VALUE",     0,  "The salt" },
	{ "user",      'u', "USERNAME",  0,  "The name of the user" },
	{ "verbose",   'v', 0,           0,  "Verbose output" },
	{ 0 }
};

struct arguments_user {
	char *username;
	uint8_t *salt;
	char *password;
	uint32_t flags;
	bool verbose;
};

static error_t parse_opt_user(int key, char *arg, struct argp_state *state)
{
	struct arguments_user *arguments =
		(struct arguments_user *)state->input;

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

static struct argp argp_user = {
	options_user,
	parse_opt_user,
	args_doc,
	doc_user
};

int user_main(int argc, char *argv[])
{
	int res = -1;
	struct arguments_user arg;

	arg.username = NULL;
	arg.salt = NULL;
	arg.password = NULL;
	arg.flags = 0;
	arg.verbose = false;

	argp_parse(&argp_user, argc, argv, 0, 0, &arg);

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
		debug_dump_users();
	}

	return res;
}

/*******************************************************************************
 * Subcommand: Measure
 ******************************************************************************/
static char doc_measure[] = "'locki measure', is used to create and manage users.";

static struct argp_option options_measure[] = {
	{ "data",      'd', "DATA",      0,  "Data to measure" },
	{ "password",  'p', "VALUE",     0,  "Authentication password" },
	{ "reg",       'r', "ID",        0,  "Register ID" },
	{ "user",      'u', "USERNAME",  0,  "The name of the user" },
	{ "verbose",   'v', 0,           0,  "Verbose output" },
	{ 0 }
};

struct arguments_measure {
	char *username;
	char *password;
	char *reg;
	char *data;
	bool verbose;
};

static error_t parse_opt_measure(int key, char *arg, struct argp_state *state)
{
	struct arguments_measure *arguments =
		(struct arguments_measure *)state->input;

	switch (key) {
	case 'd':
		arguments->data = arg;
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

static struct argp argp_measure = {
	options_measure,
	parse_opt_measure,
	args_doc,
	doc_measure
};

int measure_main(int argc, char *argv[])
{
	int res = -1;
	struct arguments_measure arg;

	arg.username = NULL;
	arg.password = NULL;
	arg.reg = NULL;
	arg.data = NULL;
	arg.verbose = false;

	argp_parse(&argp_measure, argc, argv, 0, 0, &arg);

	verbose = arg.verbose;


	if (arg.username && arg.password) {
		res = measure(arg.username, strlen(arg.username),
			      NULL, 0,
			      (uint8_t *)arg.reg, strlen(arg.reg),
			      (uint8_t *)arg.data, strlen(arg.data));
		printf("Measure: %s\n", arg.username);
		debug_dump_users();
	}

	return res;
}

/*******************************************************************************
 * Main
 ******************************************************************************/
int main(int argc, char *argv[])
{
	int res = -1;

	if (argc > 1 && (strcmp(argv[1], "user") == 0)) {
		res = user_main(argc-1, &argv[1]);
	} else if (argc > 1 && (strcmp(argv[1], "measure") == 0)) {
		res = measure_main(argc-1, &argv[1]);
	} else {
		print_help();
	}

	return res;
}
