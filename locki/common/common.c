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
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>

#include <common.h>

#define DEBUG

#ifdef DEBUG
void hexdump_ascii(const uint8_t *data, size_t len) {
	size_t i;
	for (i = 0; i < len; i += 16) {
		size_t j;
		printf("%08x  ", (unsigned int)i);
		for (j = 0; j < 16; j++) {
			if (i + j < len) {
				printf("%02x ", data[i + j]);
			} else {
				printf("   ");
			}
		}
		printf(" ");
		for (j = 0; j < 16; j++) {
			if (i + j < len) {
				printf("%c", isprint(data[i + j]) ? data[i + j] : '.');
			}
		}
		printf("\n");
	}
}
#else
static void hexdump_ascii(const uint8_t *data __maybe_unused,
			  size_t len __maybe_unused) { }
#endif

#define TAF(name) case name: return #name

/*
 * Should be kept in sync with the defines in locki_ta.h
 */
const char *taf_to_str(uint32_t cmd_id)
{
	switch (cmd_id) {
	TAF(TA_LOCKI_CMD_ADD_KEY);
	TAF(TA_LOCKI_CMD_GENERATE_KEY);
	TAF(TA_LOCKI_CMD_RESET);
	TAF(TA_LOCKI_CMD_CONFIGURE);
	TAF(TA_LOCKI_CMD_STATUS);
	TAF(TA_LOCKI_CMD_MEASURE);
	TAF(TA_LOCKI_CMD_GET_MEASURE);
	TAF(TA_LOCKI_CMD_CREATE_USER);
	TAF(TA_LOCKI_CMD_DEBUG_DUMP_USERS);
	TAF(TA_LOCKI_CMD_DEBUG_DUMP_REGISTERS);
	default:
		return "Unknown TAF id";
	}
}
