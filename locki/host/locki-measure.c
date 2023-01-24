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
	{ "password",  'p', "VALUE",     0,  "Authentication password" },
	{ "reg",       'r', "ID",        0,  "Register ID" },
	{ "user",      'u', "USERNAME",  0,  "The name of the user" },
	{ "verbose",   'v', 0,           0,  "Verbose output" },
	{ 0 }
};

struct arguments {
	char *username;
	char *password;
	char *reg;
	char *data;
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

int measure_main(int argc, char *argv[])
{
	int res = -1;
	struct arguments arg;

	arg.username = NULL;
	arg.password = NULL;
	arg.reg = NULL;
	arg.data = NULL;
	arg.verbose = false;

	argp_parse(&argp, argc, argv, 0, 0, &arg);

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
