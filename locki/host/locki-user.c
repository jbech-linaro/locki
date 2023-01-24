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
		debug_dump_users();
	}

	return res;
}
