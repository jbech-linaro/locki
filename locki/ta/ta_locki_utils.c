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
#include <pta_system.h>

#include <tee_internal_api.h>

#include <ta_locki_utils.h>

TEE_Result get_ta_unique_key(uint8_t *key, uint8_t key_size,
			     uint8_t *extra, uint16_t extra_size)
{
	static const TEE_UUID system_uuid = PTA_SYSTEM_UUID;
	TEE_Param params[4] = { 0 };
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_TASessionHandle handle = TEE_HANDLE_NULL;
	uint32_t ret_origin = 0;
	uint32_t param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					       TEE_PARAM_TYPE_MEMREF_OUTPUT,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE);
	if (!key)
		return TEE_ERROR_BAD_PARAMETERS;

	res = TEE_OpenTASession(&system_uuid, 0, 0, NULL, &handle, &ret_origin);
	if (res != TEE_SUCCESS)
		return TEE_ERROR_GENERIC;

	/* To provide salt for the generated key. */
	if (extra && extra_size > 0) {
		params[0].memref.buffer = extra;
		params[0].memref.size = extra_size;
	}

	params[1].memref.buffer = key;
	params[1].memref.size = key_size;
	res = TEE_InvokeTACommand(handle, 100, PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY,
				  param_types, params, &ret_origin);

	TEE_CloseTASession(handle);

	return res;
}

TEE_Result get_random_nbr(uint8_t *nbr, uint32_t size)
{
	void *buf = NULL;
	if (!nbr)
		return TEE_ERROR_BAD_PARAMETERS;

	buf = TEE_Malloc(size, 0);
	if (!buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	DMSG("Generating random data over %u bytes.", size);
	TEE_GenerateRandom(buf, size);
	TEE_MemMove(nbr, buf, size);
	TEE_Free(buf);

	return TEE_SUCCESS;
}
