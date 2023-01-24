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
	printf("  user        For user administration\n");
	printf("  measure     To make measurements\n");
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
	else
		print_help();

	return res;
}
