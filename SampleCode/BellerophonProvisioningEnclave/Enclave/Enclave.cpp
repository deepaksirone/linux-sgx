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
#include "sgx_tcrypto.h"
#include "sgx_utils.h"

#define ALG_RSA_OAEP_3072   1
#ifdef  __cplusplus
#define se_static_assert(e) static_assert(e, "static assert error")
#else
#define se_static_assert(e) typedef char ASSERT_CONCAT(assert_line, __LINE__)[(e)?1:-1] STATIC_ASSERT_UNUSED_ATTRIBUTE
#endif

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


typedef enum _pve_status_t
{
     PVEC_SUCCESS = 0,
     PVEC_PARAMETER_ERROR,
     PVEC_INSUFFICIENT_MEMORY_ERROR,
     PVEC_READ_RAND_ERROR,
     PVEC_SIGRL_INTEGRITY_CHECK_ERROR,
     PVEC_MALLOC_ERROR,
     PVEC_EPID_BLOB_ERROR,
     PVEC_SE_ERROR,
     PVEC_TCRYPTO_ERROR,
     PVEC_MSG_ERROR,
     PVEC_PEK_SIGN_ERROR,
     PVEC_XEGDSK_SIGN_ERROR,
     PVEC_INTEGER_OVERFLOW_ERROR,
     PVEC_SEAL_ERROR,
     PVEC_EPID_ERROR,
     PVEC_REVOKED_ERROR,
     PVEC_UNSUPPORTED_VERSION_ERROR,
     PVEC_INVALID_CPU_ISV_SVN,
     PVEC_INVALID_EPID_KEY,
     PVEC_UNEXPECTED_ERROR            /*unknown error which should never happen, it indicates there're internal logical error in PvE's code*/
}pve_status_t;

pve_status_t sgx_error_to_pve_error(sgx_status_t status)
{
    switch(status){
    case SGX_SUCCESS:
        return PVEC_SUCCESS;
    case SGX_ERROR_OUT_OF_MEMORY:
        return PVEC_MALLOC_ERROR;
    case SGX_ERROR_INVALID_CPUSVN:
    case SGX_ERROR_INVALID_ISVSVN:
        return PVEC_INVALID_CPU_ISV_SVN;
    default:
        return PVEC_SE_ERROR;
    }
}

uint32_t bellerophon_gen_prov_msg1_data_wrapper(const signed_pek_t *pek,
    const sgx_target_info_t *pce_target_info,
    sgx_report_t *pek_report) {
	
	pve_status_t ret = PVEC_SUCCESS;
	sgx_status_t sgx_status = SGX_SUCCESS;
	uint8_t pek_result = SGX_EC_INVALID_SIGNATURE;
	sgx_report_data_t report_data = {0};
	//extended_epid_group_blob_t local_xegb;
	sgx_sha_state_handle_t sha_handle = NULL;
	uint8_t crypto_suite = ALG_RSA_OAEP_3072;

	static_assert(sizeof(pek->n) == 384, "pek.n should be 384 bytes");
	//sgx_status = verify_xegb_with_default(xegb, &pek_result, local_xegb);
	//if(SGX_SUCCESS != sgx_status){
	//	ret = sgx_error_to_pve_error(sgx_status);
	//	goto ret_point;
	//} else if(pek_result != SGX_EC_VALID) {
	//	ret = PVEC_XEGDSK_SIGN_ERROR;
	//	goto ret_point;
	//}
	
	//TODO: Enable this check later
	//sgx_status = check_pek_signature(pek, (sgx_ec256_public_t*)local_xegb.pek_sk, &pek_result);
	//if(SGX_SUCCESS != sgx_status) {
	//	ret = sgx_error_to_pve_error(sgx_status);
	//	goto ret_point;
	//} else if(pek_result != SGX_EC_VALID) {
	//	ret = PVEC_PEK_SIGN_ERROR; //use a special error code to indicate PEK Signature error
	//	goto ret_point;
	//}

	se_static_assert(sizeof(report_data)>=sizeof(sgx_sha256_hash_t)); /*hash size is too large to be hold by report*/


    //report_data = SHA256(crypto_suite||public_key)||0-padding
	do {
		sgx_status = sgx_sha256_init(&sha_handle);
		if (SGX_SUCCESS != sgx_status)
			break;
		sgx_status = sgx_sha256_update(&crypto_suite, sizeof(uint8_t), sha_handle);
        	if (SGX_SUCCESS != sgx_status)
			break;
        //(MOD followed by e)
		sgx_status = sgx_sha256_update(pek->n, sizeof(pek->n), sha_handle);
        	if (SGX_SUCCESS != sgx_status)
			break;
		sgx_status = sgx_sha256_update(pek->e, sizeof(pek->e), sha_handle);
		if (SGX_SUCCESS != sgx_status)
			break;
		sgx_status = sgx_sha256_get_hash(sha_handle, reinterpret_cast<sgx_sha256_hash_t *>(&report_data));
	} while (0);
	if (sha_handle != NULL)
		sgx_sha256_close(sha_handle);
	if(SGX_SUCCESS != sgx_status) {
		ret = sgx_error_to_pve_error(sgx_status);
		goto ret_point;
	}

    /*if((pce_target_info.attributes.flags & SGX_FLAGS_PROVISION_KEY)!=SGX_FLAGS_PROVISION_KEY ||
        (pce_target_info.attributes.flags & SGX_FLAGS_DEBUG) != 0){
        //PCE must have access to provisioning key
        //Can't be debug PCE
        ret = PVEC_PARAMETER_ERROR;
        goto ret_point;
    }*/

    	sgx_status = sgx_create_report(pce_target_info, &report_data, pek_report);
    	if(SGX_SUCCESS != sgx_status){
        	ret = sgx_error_to_pve_error(sgx_status);
        	goto ret_point;
    	}

ret_point:
    if(PVEC_SUCCESS != ret) {//clear critical output data on error
        (void)memset_s(pek_report, sizeof(*pek_report), 0, sizeof(*pek_report));
    }

    return ret;
}



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
