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
	REQUIRE_EQ(initialize(), 0);
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
 * This will create a user that will use salt, but since no salt has been
 * provided, the TA will generate a random salt for us. In addition to that,
 * since the USER_TA_UNIQUE_PASSWORD is set, that will also be used when
 * creating the password. We end up with:
 *   derived password = sha256(provided password | random_salt | ta_unique_key)
 */
TEST(user, create_user_salt_ta_unique)
{
	char username[] = "user-salt-rand-with-ta-uniq";
	char password[] = "user-salt-rand-with-ta-uniq";
	uint32_t flags = USER_SALT_PASSWORD | USER_TA_UNIQUE_PASSWORD;
	CHECK_EQ(create_user(username, strlen(username), password,
			     strlen(password), NULL, 0, flags),
		 0);
}

/*
 * This will create a user that will use salt, with a user provided salt.
 * In addition to that, since the USER_TA_UNIQUE_PASSWORD is set, that will also
 * be used when creating the password. We end up with:
 *   derived password = sha256(provided password | provided salt | ta_unique_key(provided salt)
 */
TEST(user, create_user_salt_ta_unique_salt)
{
	char username[] = "user-salt-provided-with-ta-uniq";
	char password[] = "user-salt-provided-with-ta-uniq";
	uint8_t salt[] = { 0x30, 0x31, 0x32, 0x33 };
	uint32_t flags = USER_SALT_PASSWORD | USER_TA_UNIQUE_PASSWORD;
	CHECK_EQ(create_user(username, strlen(username), password,
			     strlen(password), salt, sizeof(salt), flags),
		 0);
}

/*
 * This will create a user that doesn't enable salt. Since the
 * USER_TA_UNIQUE_PASSWORD is set, the TA unique key will be used as part of
 * salting the password. I.e., we end up with:
 *   derived password = sha256(provided password | ta_unique_key)
 */
TEST(user, create_user_salt_ta_unique_no_salt)
{
	char username[] = "user-salt-with-ta-uniq-no-salt";
	char password[] = "user-salt-with-ta-uniq-no-salt";
	uint32_t flags = USER_TA_UNIQUE_PASSWORD;
	CHECK_EQ(create_user(username, strlen(username), password,
			     strlen(password), NULL, 0, flags),
		 0);
}

/*
 * Creates a user that allows unauthenticated (password less) measures. This
 * user also enabled and uses a provided salt and leverage the TA unique keys to
 * derive it's password.
 */
TEST(user, create_user_unauthenticated_measure_ta_unique)
{
	char username[] = "user-unauth-measure-ta-uniq";
	char password[] = "abc";
	uint8_t salt[] = { 0x30, 0x31, 0x32, 0x33 };
	uint32_t flags = USER_SALT_PASSWORD | USER_UNAUTHENTICATED_MEASURE |
			 USER_TA_UNIQUE_PASSWORD;
	CHECK_EQ(create_user(username, strlen(username), password,
			     strlen(password), salt, sizeof(salt), flags),
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
	char too_long_username[] = "012345678901234567890123456789012";
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
	CHECK_NE(measure(username, strlen(username), NULL, sizeof(password),
			 reg, sizeof(reg), data, sizeof(data)),
			 0);

	/* No data provided */
	CHECK_NE(measure(username, strlen(username), password, sizeof(password),
			 reg, sizeof(reg), NULL, sizeof(data)),
		 0);

	/* Data size = 0 */
	CHECK_NE(measure(username, strlen(username), password, sizeof(password),
			 reg, sizeof(reg), data, 0),
		 0);

	/* Data size = 0 */
	CHECK_NE(measure(too_long_username, strlen(too_long_username), password,
			 sizeof(password), reg, sizeof(reg), data,
			 sizeof(data)),
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
	CHECK_BUF_EQ(digest, expected1, sizeof(expected1));

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
	CHECK_BUF_EQ(digest, expected2, sizeof(expected2));

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
	REQUIRE_EQ(measure(username, strlen(username), NULL, 0, reg,
			   sizeof(reg), data, sizeof(data)),
		   0);
	REQUIRE_EQ(get_measure(username, strlen(username), NULL, 0, reg,
			       sizeof(reg), digest),
		   0);
	CHECK_BUF_EQ(digest, expected1, sizeof(expected1));

	/*
	 * Hash(32 * '0x0' || abc || abc)
	 *   -> expected: 0f25de757a05fdcd69becaeb50675b3d752b78fd31929cdbc8352b5defb683a1
	*/
	REQUIRE_EQ(measure(username, strlen(username), NULL, 0, reg,
			   sizeof(reg), data, sizeof(data)),
		   0);
	REQUIRE_EQ(get_measure(username, strlen(username), NULL, 0, reg,
			       sizeof(reg), digest),
		   0);
	CHECK_BUF_EQ(digest, expected2, sizeof(expected2));
}

/*
 * This tests that the measurements are working as expected, when having the
 * USER_TA_UNIQUE_PASSWORD flag set.
 *
 * Pre-condition: Successfully run test (user, create_user_salt_ta_unique)
 */
TEST(measure, measure_normal_ta_unique)
{
	char password[] = "user-salt-rand-with-ta-uniq";
	char username[] = "user-salt-rand-with-ta-uniq";
	uint8_t data[] =  { 'a', 'b', 'c' };
	uint8_t digest[32]; /* FIXME: Use a SHA256 length define */
	uint8_t reg[] = { 0x1 };
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
	CHECK_BUF_EQ(digest, expected1, sizeof(expected1));

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
	CHECK_BUF_EQ(digest, expected2, sizeof(expected2));
}

TEST(measure, measure_unauthenticated_ta_unique)
{
	char username[] = "user-unauth-measure-ta-uniq";
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
	REQUIRE_EQ(measure(username, strlen(username), NULL, 0, reg,
			   sizeof(reg), data, sizeof(data)),
		   0);
	REQUIRE_EQ(get_measure(username, strlen(username), NULL, 0, reg,
			       sizeof(reg), digest),
		   0);
	CHECK_BUF_EQ(digest, expected1, sizeof(expected1));

	/*
	 * Hash(32 * '0x0' || abc || abc)
	 *   -> expected: 0f25de757a05fdcd69becaeb50675b3d752b78fd31929cdbc8352b5defb683a1
	*/
	REQUIRE_EQ(measure(username, strlen(username), NULL, 0, reg,
			   sizeof(reg), data, sizeof(data)),
		   0);
	REQUIRE_EQ(get_measure(username, strlen(username), NULL, 0, reg,
			       sizeof(reg), digest),
		   0);
	CHECK_BUF_EQ(digest, expected2, sizeof(expected2));
}

/*
 * Testing various unsupported parameters for the generate_key function.
 */
TEST(keys, bad_parameters)
{
	char username[] = "user-bad-parameter";
	char password[] = "user-bad-parameter";
	uint8_t reg[] = { 0x1 };
	uint32_t attributes = 0;
	uint32_t key_handle = 1;

	/* No user name */
	CHECK_NE(generate_key(NULL, strlen(username),
			      password, strlen(password),
			      reg, sizeof(reg),
			      key_handle, attributes),
		 0);

	/* Short username */
	CHECK_NE(generate_key(username, 0,
			      password, strlen(password),
			      reg, sizeof(reg),
			      key_handle, attributes),
		 0);

	/* No password */
	CHECK_NE(generate_key(username, strlen(username),
			      NULL, strlen(password),
			      reg, sizeof(reg),
			      key_handle, attributes),
		 0);

	/* Short password */
	CHECK_NE(generate_key(username, strlen(username),
			      password, 0,
			      reg, sizeof(reg),
			      key_handle, attributes),
		 0);

	/* No register */
	CHECK_NE(generate_key(username, strlen(username),
			      password, strlen(password),
			      NULL, sizeof(reg),
			      key_handle, attributes),
		 0);

	/* Short register size */
	CHECK_NE(generate_key(username, strlen(username),
			      password, strlen(password),
			      reg, 0,
			      key_handle, attributes),
		 0);
}

TEST(keys, generate_key)
{
	char username[] = "user-gen-key";
	char password[] = "user-gen-key";
	uint8_t data[] =  { 'a', 'b', 'c' };
	uint8_t reg[] = { 0x1 };
	uint8_t salt[] = { 0x30, 0x31, 0x32, 0x33 };
	uint32_t attributes = 0;
	uint32_t flags = USER_SALT_PASSWORD;
	uint32_t key_handle = 1;

	/*
	 * Add a new user to make it easiers to run this test as a standalone
	 * test
	 */
	REQUIRE_EQ(create_user(username, strlen(username),
			       password, strlen(password),
			       salt, sizeof(salt),
			       flags),
		 0);

	/* We also need a value measurement to refer to. */
	REQUIRE_EQ(measure(username, strlen(username),
			   password, strlen(password),
			   reg, sizeof(reg),
			   data, sizeof(data)),
		   0);

	CHECK_EQ(generate_key(username, strlen(username),
			      password, strlen(password),
			      reg, sizeof(reg),
			      key_handle, attributes),
		 0);

	CHECK_NE(generate_key(username, strlen(username),
			      password, strlen(password),
			      reg, sizeof(reg),
			      key_handle, attributes),
		 0);
}

/*
 * This tests that it's possible to sign a measurement with the users derived
 * password.
 *
 * Note that this test is extremely fragile since:
 * a) It's dependant on the order of previous tests in the little test suite.
 * b) It's necessary that the same user, password, salt and flags have been
 * used.
 * c) That the amount of prior measurements done on the same register is the
 * same.
 *
 * In short, this test strongly depends on successful runs of tests:
 *    user.create_user
 *    measure.measure_normal
 *
 * FIXME: It would probably be better to  changes this to create a user, make
 * the measurement and then retrieve it. That would isolate the test.
 */
TEST(measure, retrieve_signed_measurement)
{
	char username[] = "user";
	char password[] = "user";
	uint8_t reg[] = { 0x1 };
	uint8_t digest[32]; /* FIXME: Use a SHA256 length define */
	uint8_t expected[] = {
		0x7d, 0x56, 0x71, 0xcd, 0x07, 0x1b, 0x4f, 0x80,
		0xb9, 0xbc, 0x77, 0x34, 0x90, 0xcd, 0xd5, 0xaf,
		0x1c, 0xcd, 0x82, 0xab, 0x49, 0xa1, 0xd0, 0xb1,
		0x69, 0x5b, 0x22, 0xec, 0xc8, 0x01, 0xbf, 0xaf };

	CHECK_EQ(get_signed_measure(username, strlen(username), password,
				    strlen(password), reg, sizeof(reg),
				    digest),
		 0);
	CHECK_BUF_EQ(digest, expected, sizeof(expected));
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

TEST(debug, dump_keys)
{
	debug_dump_keys();
}

#if 0
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
#endif

/*
 * This function has to be last in this file, don't move it!
 */
TEST(system, shutdown)
{
	CHECK_EQ(terminate(), 0);
}
