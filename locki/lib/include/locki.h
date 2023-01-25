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
#ifndef ATTEST_H
#define ATTEST_H

#include <stdint.h>
#include <stdio.h>

#include <common.h>

int add_key(char *identity, char *key, uint8_t *data, size_t len);
int configure(char *password, size_t len);
int create_key(void);
int create_user(char *username, size_t username_len, char *password, size_t password_len, uint8_t *salt, size_t salt_len, uint32_t flags);
int get_measure(char *username, size_t username_len, char *password, size_t password_len, uint8_t *reg, size_t reg_len, uint8_t *digest);
void hexdump_ascii(const uint8_t *data, size_t len);
void hexdump(const uint8_t *data, size_t len);
int initialize(void);
int load_key_from_file(const char *filename, uint8_t **data, size_t *len);
int measure(char *username, size_t username_len, char *password, size_t password_len, uint8_t *reg, size_t reg_len, uint8_t *data, size_t data_size);
int reset(char *password, size_t len);
int status(struct sys_state *status);
int terminate(void);

/* Debug functions */
int debug_dump_users(void);
int debug_dump_registers(void);

#endif
