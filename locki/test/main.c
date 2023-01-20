#include "tau/tau/tau.h"
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include <tau/tau.h>

#include <common.h>
#include <locki.h>

#define DEFAULT_KEY_FILENAME "key.bin"

TAU_MAIN()

TEST(system, initialize)
{
	CHECK_EQ(initialize(), 0);
}

TEST(setup, remove_file)
{
	remove(DEFAULT_KEY_FILENAME);
	CHECK_FALSE(access(DEFAULT_KEY_FILENAME, F_OK) == 0);
}

TEST(status, bad_parameters)
{
	CHECK_NE(status(NULL), 0);
}

#if 0
TEST(status, check_initial)
{
	struct sys_state st = { 0 };
	CHECK_EQ(status(&st), 0);
	CHECK_EQ(st.state, 0);
	CHECK_EQ(st.users, 0);
	CHECK_EQ(st.keys, 0);
}

TEST(configure, bad_parameters)
{
	CHECK_NE(configure(NULL, 0), 0);
	CHECK_NE(configure("password", 0), 0);
	CHECK_NE(configure(NULL, 1), 0);
}

TEST(configure, with_correct_password)
{
	char password[] = "correct-pw";
	CHECK_EQ(configure(password, strlen(password)), 0);
}

TEST(alg, create)
{
	struct stat st;
	create_key();
	CHECK_TRUE(access("key.bin", F_OK) == 0);

	stat(DEFAULT_KEY_FILENAME, &st);
	CHECK_EQ(st.st_size, MAX_KEY_SIZE);
}

TEST(add_key, bad_parameters)
{
	char identity[] = "joe";
	char key[] = "123";
	uint8_t *data = (uint8_t *)key;

	CHECK_NE(add_key(NULL, NULL, NULL, 0), 0);
	CHECK_NE(add_key(identity, key, data, 0), 0);
	CHECK_NE(add_key(identity, NULL, NULL, 0), 0);
}

TEST(add_key, add_ascii_key)
{
	char identity[] = "joe";
	char key[] = "123";
	CHECK_EQ(add_key(identity, key, NULL, 0), 0);
}

#if 0
TEST(configure, with_bad_password)
{
	char password[] = "incorrect-pw";
	CHECK_NE(configure(password, strlen(password)), 0);
}
#endif

TEST(reset, bad_parameters)
{
	CHECK_NE(configure(NULL, 0), 0);
	CHECK_NE(configure("password", 0), 0);
	CHECK_NE(configure(NULL, 1), 0);
}

TEST(reset, with_correct_password)
{
	char password[] = "correct-pw";
	CHECK_EQ(configure(password, strlen(password)), 0);
}

#endif

/*
 * Testing various bad input parameter, when creating a user.
 */
TEST(user, bad_parameters)
{
	char username[] = "admin";
	char password[] = "admin";
	char username_too_long[] = "012345678901234567890123456789012"; /* 33 characters */
	uint8_t salt[] = { 0x0, 0x1, 0x2, 0x3 };

	/* No username provided. */
        CHECK_NE(create_user(NULL, sizeof(username), password, sizeof(password),
                             salt, sizeof(salt), 0),
                 0);

        /* Username length = 0. */
        CHECK_NE(create_user(username, 0, password, sizeof(password), salt,
                             sizeof(salt), 0),
                 0);

        /* Password provided, but length = 0 */
        CHECK_NE(create_user(username, strlen(username), password, 0, salt,
                             sizeof(salt), 0),
                 0);

	/* Username longer than the maximum allowed (32). */
        CHECK_NE(create_user(username_too_long, strlen(username_too_long),
                             password, 0, salt, sizeof(salt), 0),
                 0);
}

/*
 * Creates a regular user that uses a provided salt.
 */
TEST(user, create_user)
{
	char username[] = "user";
	char password[] = "user";
	uint8_t salt[] = { 0x30, 0x31, 0x32, 0x33 };
	uint32_t flags = USER_SALT_PASSWORD;
        CHECK_EQ(create_user(username, strlen(username), password,
                             strlen(password), salt, sizeof(salt), flags),
                 0);
}

/*
 * Creates a user that allows unauthenticated (password less) measures. This
 * user also enabled and uses a provided salt.
 */
TEST(user, create_user_unauthenticated_measure)
{
	char username[] = "user-unauthenticated-measure";
	char password[] = "abc";
	uint8_t salt[] = { 0x30, 0x31, 0x32, 0x33 };
	uint32_t flags = USER_SALT_PASSWORD | USER_UNAUTHENTICATED_MEASURE;
        CHECK_EQ(create_user(username, strlen(username), password,
                             strlen(password), salt, sizeof(salt), flags),
                 0);
}

/*
 * Creates a user that doesn't use any salt at all.
 */
TEST(user, create_user_salt_not_used)
{
	char username[] = "user-salt-not-used";
	char password[] = "user-salt-not-used";
	uint32_t flags = 0;
        CHECK_EQ(create_user(username, strlen(username), password,
                             strlen(password), NULL, 0, flags),
                 0);
}

/*
 * This tests that it's possible to create a user that indicates that salt
 * should be used, but the user doesn't provide the salt by itself. Instead it's
 * up to TA to generate a salt that will be used. Since this will be random
 * number, there is no easy way to check the result other than look at the
 * secure UART when DEBUG is enabled.
 *
 * Worth noting here, that since there is no salt provided, the password will
 * also be random every time this is running. So for this to be useful for an
 * external client verifying signed measurements, this should give back the salt
 * either at creation time or via a separate command.
 */
TEST(user, create_user_salt_not_used_but_set)
{
        char username[] = "user-salt-not-used-but-set";
        char password[] = "user-salt-not-used-but-set";
        uint32_t flags = USER_SALT_PASSWORD;
        CHECK_EQ(create_user(username, strlen(username), password,
                             strlen(password), NULL, 0, flags),
                 0);
}

/*
 * Testing various bad parameters when trying to make a measurement. Note that
 * this test, depends on that a user with username 'user' and password 'user'
 * previously has been created.
 */
TEST(measure, bad_parameters)
{
        char username[] = "user";
        char password[] = "user";
        uint8_t reg[] = { 0x1 };
        uint8_t data[]= { 'a', 'b', 'c' };

	/* No data provided */
        CHECK_NE(measure(username, strlen(username), password, strlen(password),
                         reg, sizeof(reg), NULL, 0),
                 0);

	/* No data provided */
        CHECK_NE(measure(username, strlen(username), NULL, 0, reg, sizeof(reg),
                         data, sizeof(data)),
                 0);

	/* Password length = 0 */
        CHECK_NE(measure(username, strlen(username), password, 0, reg,
                         sizeof(reg), data, sizeof(data)),
                 0);

	/* No password provided */
        CHECK_NE(measure(username, strlen(username), NULL, sizeof(password), reg,
                         sizeof(reg), data, sizeof(data)),
                 0);

	/* No data provided */
        CHECK_NE(measure(username, strlen(username), password, sizeof(password),
                         reg, sizeof(reg), NULL, sizeof(data)),
                 0);

	/* Data size = 0 */
        CHECK_NE(measure(username, strlen(username), password, sizeof(password),
                         reg, sizeof(reg), data, 0),
                 0);
}

TEST(measure, measure_normal)
{
	char username[] = "user";
	char password[] = "user";
	char incorrect_password[] = "wrong";
	uint8_t reg[] = { 0x1 };
	uint8_t data[] =  { 'a', 'b', 'c' };
	uint8_t digest[32]; /* FIXME: Use a SHA256 length define */
	uint8_t expected1[] = {
		0x36, 0x5a, 0xa7, 0xd8,  0xf7, 0xf9, 0x40, 0x2c,
		0x4b, 0x94, 0x34, 0x50,  0x2b, 0x4c, 0xc8, 0x9d,
		0xdb, 0x09, 0xfe, 0x50,  0xd7, 0xcd, 0x95, 0xb4,
		0x93, 0xb8, 0x34, 0xc6,  0x2d, 0x5a, 0x53, 0x70 };

	uint8_t expected2[] = {
		0x0f, 0x25, 0xde, 0x75,  0x7a, 0x05, 0xfd, 0xcd,
		0x69, 0xbe, 0xca, 0xeb,  0x50, 0x67, 0x5b, 0x3d,
		0x75, 0x2b, 0x78, 0xfd,  0x31, 0x92, 0x9c, 0xdb,
		0xc8, 0x35, 0x2b, 0x5d,  0xef, 0xb6, 0x83, 0xa1 };

	/*
	 * Hash(32 * '0x0' || abc)
	 *   -> expected:
	 * 365aa7d8f7f9402c4b9434502b4cc89ddb09fe50d7cd95b493b834c62d5a5370
	 */
        REQUIRE_EQ(measure(username, strlen(username), password,
                           strlen(password), reg, sizeof(reg), data,
                           sizeof(data)),
                   0);
        REQUIRE_EQ(get_measure(username, strlen(username), password,
                               strlen(password), reg, sizeof(reg), digest),
                   0);
        CHECK_EQ(memcmp(digest, expected1, sizeof(expected1)), 0);

        /*
	 * Hash(32 * '0x0' || abc || abc)
	 *   -> expected:
	 * 0f25de757a05fdcd69becaeb50675b3d752b78fd31929cdbc8352b5defb683a1
	 */
        REQUIRE_EQ(measure(username, strlen(username), password,
                           strlen(password), reg, sizeof(reg), data,
                           sizeof(data)),
                   0);
        REQUIRE_EQ(get_measure(username, strlen(username), password,
                               strlen(password), reg, sizeof(reg), digest),
                   0);
        CHECK_EQ(memcmp(digest, expected2, sizeof(expected2)), 0);

        /* Try authenticated measure, with incorrect passsword */
        CHECK_NE(measure(username, strlen(username), incorrect_password,
                         strlen(incorrect_password), reg, sizeof(reg), data,
                         sizeof(data)),
                 0);
}

TEST(measure, measure_unauthenticated)
{
	char username[] = "user-unauthenticated";
	uint8_t reg[] = { 0x1 };
	uint8_t data[] =  { 'a', 'b', 'c' };
	uint8_t digest[32]; /* FIXME: Use a SHA256 length define */
	uint8_t expected1[] = {
		0x36, 0x5a, 0xa7, 0xd8,  0xf7, 0xf9, 0x40, 0x2c,
		0x4b, 0x94, 0x34, 0x50,  0x2b, 0x4c, 0xc8, 0x9d,
		0xdb, 0x09, 0xfe, 0x50,  0xd7, 0xcd, 0x95, 0xb4,
		0x93, 0xb8, 0x34, 0xc6,  0x2d, 0x5a, 0x53, 0x70 };

	uint8_t expected2[] = {
		0x0f, 0x25, 0xde, 0x75,  0x7a, 0x05, 0xfd, 0xcd,
		0x69, 0xbe, 0xca, 0xeb,  0x50, 0x67, 0x5b, 0x3d,
		0x75, 0x2b, 0x78, 0xfd,  0x31, 0x92, 0x9c, 0xdb,
		0xc8, 0x35, 0x2b, 0x5d,  0xef, 0xb6, 0x83, 0xa1 };

	/*
	 * Hash(32 * '0x0' || abc)
	 *   -> expected: 365aa7d8f7f9402c4b9434502b4cc89ddb09fe50d7cd95b493b834c62d5a5370
	 */
        REQUIRE_EQ(measure(username, strlen(username), NULL, 0, reg, sizeof(reg),
                         data, sizeof(data)),
                 0);
        REQUIRE_EQ(get_measure(username, strlen(username), NULL, 0, reg,
                             sizeof(reg), digest),
                 0);
        CHECK_EQ(memcmp(digest, expected1, sizeof(expected1)), 0);

	/*
	 * Hash(32 * '0x0' || abc || abc)
	 *   -> expected: 0f25de757a05fdcd69becaeb50675b3d752b78fd31929cdbc8352b5defb683a1
	 */
        REQUIRE_EQ(measure(username, strlen(username), NULL, 0, reg, sizeof(reg),
                         data, sizeof(data)),
                 0);
        REQUIRE_EQ(get_measure(username, strlen(username), NULL, 0, reg,
                             sizeof(reg), digest),
                 0);
        CHECK_EQ(memcmp(digest, expected2, sizeof(expected2)), 0);
}

/*
 * Dump all existing users into the secure UART.
 * FIMXE: Should not be available on debug builds.
 */
TEST(debug, dump_users)
{
	debug_dump_users();
}

/*
 * Dump all existing registers into the secure UART.
 * FIMXE: Should not be available on debug builds.
 */
TEST(debug, dump_registers)
{
	debug_dump_registers();
}

/*
 * This function has to be last in this file, don't move it!
 */
TEST(system, shutdown)
{
	CHECK_EQ(terminate(), 0);
}
