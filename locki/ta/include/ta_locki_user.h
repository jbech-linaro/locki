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
#ifndef _LOCKI_USER_H
#define _LOCKI_USER_H

#include <stdint.h>
#include <sys/queue.h>

#include <tee_api_types.h>
#include <utee_defines.h>

struct user {
	uint8_t name[32];
	uint8_t name_len;
	uint8_t password[TEE_SHA256_HASH_SIZE]; /* Run via Argon or PBKDF2? */
	uint8_t password_len;
	uint8_t salt[TEE_SHA256_HASH_SIZE];
	uint8_t salt_len;
	uint32_t flags;
	TAILQ_ENTRY(user) entry;
};


struct user* find_user(uint8_t *username, size_t username_len);
struct user* find_and_validate_user(uint8_t *username, size_t username_len,
				    uint8_t *password, size_t password_len);
TEE_Result create_user(uint8_t *username, uint32_t username_len,
		       uint8_t *password, uint32_t password_len,
		       uint8_t *salt, uint32_t salt_len,
		       uint32_t flags);
uint32_t nbr_of_users(void);

#endif
