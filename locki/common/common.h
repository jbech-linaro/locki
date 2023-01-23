#ifndef	COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stddef.h>

#include <locki_ta.h>

#define MAX_KEY_SIZE 32

/* FIXME: Figure out why we cannot use the defines from util.h */
#ifndef BIT
#define BIT(nr)	(1 << (nr))
#endif
#define IS_SET(x, mask) ((x & mask) == mask)
#define IS_UNSET(x, mask) ((x & mask) == 0)

/*
 * Defines flags used when creating a user.
 */
#define USER_ADMIN			BIT(0)
#define USER_SALT_PASSWORD		BIT(1)
#define USER_UNAUTHENTICATED_MEASURE	BIT(2)
#define USER_TA_UNIQUE_PASSWORD		BIT(3)

struct sys_state {
	uint32_t state;
	uint32_t users;
	uint32_t keys;
};

void hexdump_ascii(const uint8_t *data, size_t len);

const char *taf_to_str(uint32_t cmd_id);

#endif
