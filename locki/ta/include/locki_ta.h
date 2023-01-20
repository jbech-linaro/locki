/*
 * Copyright (c) 2023, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
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
