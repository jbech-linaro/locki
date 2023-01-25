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
#ifndef TA_LOCKI_H
#define TA_LOCKI_H

#define LOCKI_TA_UUID \
	{ 0xf13982ac, 0x0ef8, 0x46a6, { 0xb1, 0x2c, 0xea, 0x79, 0x15, 0x4c, 0x30, 0xe2 } }

/* The function IDs implemented in this Trusted Application */
#define TA_LOCKI_CMD_ADD_KEY	0
#define TA_LOCKI_CMD_CREATE_KEY	1
#define TA_LOCKI_CMD_RESET	2
#define TA_LOCKI_CMD_CONFIGURE	3
#define TA_LOCKI_CMD_STATUS	4
#define TA_LOCKI_CMD_MEASURE	5
#define TA_LOCKI_CMD_GET_MEASURE	6

#define TA_LOCKI_CMD_CREATE_USER  10

#define TA_LOCKI_CMD_DEBUG_DUMP_USERS	100
#define TA_LOCKI_CMD_DEBUG_DUMP_REGISTERS	101

#endif
