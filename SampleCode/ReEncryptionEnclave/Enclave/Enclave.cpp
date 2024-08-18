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

int init_hibe()
{
        //char seed[32] = {0x0};
        int32_t out_size;

        char *hibe_setup_params = setup_hibe(5, NULL, 0, &out_size);
        if (out_size <= 0)
                return -1;
        if (out_size > 4096)
                return -2;

        hibe_setup_keys_size = out_size;
        memcpy(hibe_setup_keys, hibe_setup_params, hibe_setup_keys_size);

        return out_size;
}


int reEncryptHIBEWrappedKeys(char **hibe_keys, int hibe_keys_size, char **encapsulated_keys, char **old_identity, int old_identity_length, char **new_identity, int new_identity_length, char **re_encrypted_keys) {
	char *key = hibe_keys;
	int idx = 0;
	while(key != NULL) {
		int ret = reencrypt_data(5, (char *)hibe_setup_keys, old_identity, old_identity_size, new_identity, new_identity_size, NULL, 0, hibe_keys[idx], hibe_keys_size, encapsulated_key[idx], NULL);
		if (ret != 0)
			return ret;
		key = hibe_keys[++idx];
	}

	return 0;
}
