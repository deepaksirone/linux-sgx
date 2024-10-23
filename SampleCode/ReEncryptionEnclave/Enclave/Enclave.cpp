/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

static char hibe_setup_keys[4096];
static int32_t hibe_setup_keys_size = 0;
static int32_t hibe_pvt_key_size = 0;
static char hibe_pvt_key[4096];
static int depth_st = 0;
static int ciphertext_buf[4096];

extern "C" char *setup_hibe(int32_t depth, char *seed_buf, int32_t seed_size, int32_t *out_size);
extern "C" int decrypt_hibe_integers(int32_t depth, char *setup_params, int32_t *identity, int32_t identity_size, char *seed_buf, int32_t seed_size, char *ciphertext,
                int32_t ciphertext_size, char *encapsulated_key);
extern "C" int reencrypt_data(int32_t depth, 
				char *setup_params, 
				char **old_identity, 
				int32_t old_identity_size, 
				char **new_identity, 
				int32_t new_identity_size, 
				char *seed_buf, 
				int32_t seed_size, 
				char *ciphertext, 
				int32_t ciphertext_size, 
				char *encapsulated_key, 
				char *out_buf);

extern "C" char *get_private_key(int32_t depth, char *setup_params, int32_t *out_size);
extern "C" int decrypt_private_key(int32_t depth, 
		char *setup_params, char *private_key, char *ciphertext, int32_t ciphertext_size, char *encapsulated_key, char *out_buf);
extern "C" int re_encrypt_strings_depth(int32_t depth, char *setup_params, char *private_key, char *ciphertext, int32_t ciphertext_size, char *encapsulated_key, char *out_buf);


int init_hibe(int depth)
{
        //char seed[32] = {0x0};
        /*int32_t out_size;

        char *hibe_setup_params = setup_hibe(depth, NULL, 0, &out_size);
        if (out_size <= 0)
                return -1;
        if (out_size > 4096)
                return -2;

        hibe_setup_keys_size = out_size;
        memcpy(hibe_setup_keys, hibe_setup_params, hibe_setup_keys_size);

        return out_size;*/
	//char seed[32] = {0x0};
	int32_t out_size;

	char *hibe_setup_params = setup_hibe(depth, NULL, 0, &out_size);
	if (out_size <= 0)
		return -1;
	if (out_size > 4096)
		return -2;

	hibe_setup_keys_size = out_size;
	memcpy(hibe_setup_keys, hibe_setup_params, hibe_setup_keys_size);

	char *hibe_pk = get_private_key(depth, hibe_setup_keys, &out_size);
	if (out_size <= 0)
		return -3;
	if (out_size > 4096)
		return -4;

	hibe_pvt_key_size = out_size;
	memcpy(hibe_pvt_key, hibe_pk, hibe_pvt_key_size);

	depth_st = depth;

	return out_size;

}

int re_encrypt_wrapped_hibe_keys_string_depth(int depth, int num_iter, char *ciphertext, int32_t ciphertext_size, char *encapsulated_key, char *out_buf) {

	int ret = re_encrypt_strings_depth(depth, (char *)hibe_setup_keys, (char *)hibe_pvt_key, ciphertext, ciphertext_size, encapsulated_key, NULL);
	if (ret == 0) {
		memcpy(out_buf, ciphertext, ciphertext_size);
	}

	return ret;
}


int reEncryptHIBEWrappedKeys(char **hibe_keys, int hibe_keys_size, char **encapsulated_keys, char **old_identity, int old_identity_length, char **new_identity, int new_identity_length, char **re_encrypted_keys) {
	char *key = hibe_keys[0];
	int idx = 0;
	while(key != NULL) {
		int k = 0;
		while (k < 500) {
			int ret = reencrypt_data(10, (char *)hibe_setup_keys, old_identity, old_identity_length, new_identity, new_identity_length, NULL, 0, hibe_keys[idx], hibe_keys_size, encapsulated_keys[idx], re_encrypted_keys[idx]);
			if (ret != 0)
				return ret;
			k++;
		}
		key = hibe_keys[++idx];
	}

	return 0;
}
