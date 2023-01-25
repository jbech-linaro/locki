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
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <locki.h>
#include <locki-tool.h>

extern const char *argp_program_version;
extern const char *argp_program_bug_address;

static char doc[] = "'locki debug', is used for debugging.";
static char args_doc[] = "ARG1 ARG2";
static bool verbose;
static bool running;

static struct argp_option options[] = {
	{ "initialize",        'i', 0, 0, "Initialize the TA" },
	{ "terminate",         't', 0, 0, "Terminate the TA" },
	{ "list-users",        'u', 0, 0, "Lists all users" },
	{ "list-registers",    'r', 0, 0, "Lists all registers" },
	{ "verbose",           'v', 0, 0, "Verbose output" },
	{ 0 }
};

struct arguments {
	bool initialize;
	bool registers;
	bool terminate;
	bool users;
	bool verbose;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct arguments *arguments = (struct arguments *)state->input;

	switch (key) {
	case 'i':
		arguments->initialize = true;
		break;
	case 'r':
		arguments->registers = true;
		break;
	case 't':
		arguments->terminate = true;
		break;
	case 'u':
		arguments->users = true;
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

static void sig_handler(int sig) {
	running = false;
}

int debug_main(int argc, char *argv[])
{
	int res = -1;
	struct arguments arg = { 0 };

	signal(SIGINT, sig_handler);
	argp_parse(&argp, argc, argv, 0, 0, &arg);
	verbose = arg.verbose;
	running = true;

	if (arg.initialize) {
		printf("Initialize the TA\n");
		res = initialize();
		while(running)
			sleep(1);
	} else if (arg.terminate) {
		printf("Terminate the TA\n");
		res = terminate();
	} else if (arg.registers) {
		printf("Dump all registers\n");
		res = debug_dump_registers();
	} else if (arg.users) {
		printf("Dump all users\n");
		res = debug_dump_users();
	}

	return res;
}
