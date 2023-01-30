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
#include <sys/queue.h>

#include <tee_api_defines.h>
#include <trace.h>

#include <common.h>
#include <ta_locki_debug.h>
#include <ta_locki_keys.h>
#include <ta_locki_measure.h>

#define DEBUG

extern TAILQ_HEAD(key_list, key) key_list;
extern TAILQ_HEAD(reg_list, reg_element) reg_list;
extern TAILQ_HEAD(user_list, user) user_list;

#ifdef DEBUG
/*
 * This should NEVER EVER be enabled in a production build !!!
 */
void dump_user(struct user *u)
{
	DMSG("<<<<<<< %s >>>>>>>", u->name);
	DMSG("  password:");
	DMSG("  flags: 0x%x", u->flags);
	hexdump_ascii(u->password, u->password_len);
	if (IS_SET(u->flags, USER_SALT_PASSWORD)) {
		DMSG("  salt:");
		hexdump_ascii(u->salt, u->salt_len);
	} else
		DMSG("  salt: NOT used");
	DMSG("--------------------------");
}
#else
void dump_user(struct user *u) { (void)u }
#endif

#ifdef DEBUG
void dump_user_list(void)
{
	struct user *user = NULL;
	size_t i = 0;
	TAILQ_FOREACH(user, &user_list, entry) {
		dump_user(user);
		i++;
	}
	DMSG("In total there are %lu user(s)", i);
}
#else
void dump_user_list(void) {}
#endif

#ifdef DEBUG
void dump_register(struct reg_element *re)
{
	DMSG("id:");
	hexdump_ascii(re->id, sizeof(re->id));
	DMSG("val");
	hexdump_ascii(re->val, sizeof(re->val));
}
#else
void dump_register(struct reg_element *re) {}
#endif

#ifdef DEBUG
void dump_reg_list(void)
{
	struct reg_element *re = NULL;
	size_t i = 0;
	TAILQ_FOREACH(re, &reg_list, entry) {
		dump_register(re);
		i++;
	}
	DMSG("In total there are %lu register(s)", i);
}
#else
void dump_reg_list(void) {}
#endif

#ifdef DEBUG
void dump_key(struct key *key)
{
	DMSG("id:");
	hexdump_ascii(key->id, sizeof(key->id));
	DMSG("value");
	hexdump_ascii(key->value, sizeof(key->value));
	DMSG("key handle: 0x%08x", key->handle);
	DMSG("attributes: 0x%08x", key->attributes);
}
#else
void dump_key(struct key *key) {]
#endif

#ifdef DEBUG
void dump_key_list(void)
{
	struct key *key = NULL;
	size_t i = 0;
	TAILQ_FOREACH(key, &key_list, entry) {
		dump_key(key);
		i++;
	}
	DMSG("In total there are %lu keys(s)", i);
}
#else
void dump_key_list(void) {}
#endif
