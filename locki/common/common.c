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
	TAF(TA_LOCKI_CMD_CREATE_KEY);
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
