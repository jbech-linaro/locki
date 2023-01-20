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
