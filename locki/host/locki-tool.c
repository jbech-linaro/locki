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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <locki.h>
#include <locki-tool.h>

const char *argp_program_version = "Locki v0.1";
const char *argp_program_bug_address = "<joakim.bech@linaro.org>";

int print_help(void)
{
	printf("Usage: myprogram [OPTION]...\n\n");
	printf("Options:\n");
	printf("  key         For key generation\n");
	printf("  user        For user administration\n");
	printf("  measure     To make measurements\n");
	printf("\n");
	printf("  debug       Various debug commands\n");
	printf("\n");

	return 0;
}

/*******************************************************************************
 * Main
 ******************************************************************************/
int main(int argc, char *argv[])
{
	int res = -1;

	if (argc > 1 && (!strcmp(argv[1], "user")))
		res = user_main(argc-1, &argv[1]);
	else if (argc > 1 && (!strcmp(argv[1], "measure")))
		res = measure_main(argc-1, &argv[1]);
	else if (argc > 1 && (!strcmp(argv[1], "key")))
		res = key_main(argc-1, &argv[1]);
	else if (argc > 1 && (!strcmp(argv[1], "debug")))
		res = debug_main(argc-1, &argv[1]);
	else
		print_help();

	return res;
}
