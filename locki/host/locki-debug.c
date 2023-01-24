#include <argp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <locki.h>
#include <locki-tool.h>

extern const char *argp_program_version;
extern const char *argp_program_bug_address;

static char doc[] = "'locki debug', is used for debugging.";
static char args_doc[] = "ARG1 ARG2";
static bool verbose;

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

int debug_main(int argc, char *argv[])
{
	int res = -1;
	struct arguments arg = { 0 };

	argp_parse(&argp, argc, argv, 0, 0, &arg);

	verbose = arg.verbose;

	if (arg.initialize)
		res = initialize();
	else if (arg.terminate)
		res = terminate();
	else if (arg.registers)
		res = debug_dump_registers();
	else if (arg.users)
		res = debug_dump_users();

	return res;
}
