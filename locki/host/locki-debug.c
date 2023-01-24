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
