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


#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <chrono>
#include <iostream>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
//#include "Enclave_u.h"
#include "provisioning/server.h"
#include "type_length_value.h"
#include "PVEClass.h"

uint32_t bellerophon_gen_prov_msg1(
     pve_data_t &pve_data,
     uint8_t *msg1,
     uint32_t msg1_size);

inline uint32_t estimate_msg1_size(bool performance_rekey)
{
    size_t field0_size = CIPHER_TEXT_TLV_SIZE(RSA_3072_KEY_BYTES);
    size_t field1_0_size = CIPHER_TEXT_TLV_SIZE(RSA_3072_KEY_BYTES);
    size_t field1_1_size = PLATFORM_INFO_TLV_SIZE();
    size_t field1_2_size = performance_rekey? FLAGS_TLV_SIZE():0;
    size_t field1_size = BLOCK_CIPHER_TEXT_TLV_SIZE(field1_0_size+field1_1_size+field1_2_size);
    size_t field2_size = MAC_TLV_SIZE(MAC_SIZE);
    return static_cast<uint32_t>(PROVISION_REQUEST_HEADER_SIZE+field0_size+field1_size+field2_size); /*no checking for integer overflow since the size of msg1 is fixed and small*/
}


/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
    {
       SGX_ERROR_MEMORY_MAP_FAILURE,
        "Failed to reserve memory for the enclave.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }
    return 0;
}


extern "C" void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate */
static uint8_t encapsulated_key[] = "\xbb\xec\xc4\x55\x84\xa8\x10\x97\xbb\x9c\x1d\xd1\xd9\x2e\xf5\x7f\x1e\xc0\x86\x27\xa2\xbb\x3a\x24\x77\x15\x8e\x34\x88\x54\xeb\xf9\xee\x1a\x9e\x21\x3c\xa8\xc1\xd7\xc8\x7a\x8a\xc7\x36\x80\x0a\x07\x59\x8a\xef\x01\xe7\xc2\x6b\x2c\xa5\x5d\x2d\xac\x5d\x76\xb1\x5e\x9e\x0e\x1e\x90\xf9\x36\x40\xca\xcc\x0a\xf8\x17\x99\xdd\x42\xa8\x1a\x57\xaf\x83\x1e\xd2\x5e\x7d\x9c\xd2\x39\x33\x81\x1d\x6e\x11\x00\xc5\xf5\x8d\xf9\x03\x15\xec\x15\xa7\x76\xa4\xed\x23\x22\xd2\xc7\xcf\x54\x34\x37\x9c\xe5\x45\x13\x66\x4a\xc5\x32\x8c\xf1\x42\xf8\x81\x84\xda\x12\x18\xdd\xd1\x4f\x66\x55\x81\xcd\x57\xfc\xc5\xba\x36\xdc\x84\xe5\xe8\x53\x05\xb6\x3e\x14\xb4\xb4\xa8\x75\x45\x29\x96\xbc\xae\xc9\x3e\x4e\x8b\xf8\x18\xcd\x3d\x0c\x3b\xdc\x8c\x62\x2a\x4b\xf1\xee\x6f\xd6\x4c\xdd\x0f\xcb\x15\x86\xa5\x40\xc0\x22\xaf\x87\xac\xea\x19\xee\x12\xf2\x54\x1b\xc8\xe2\xe3\xea\x82\x62\xaa\x5c\x0b\xeb\x62\xc1\x4b\x66\x1d\xaf\x18\xea\x50\x33\xb0\x82\x7e\x2c\x63\x31\x82\x92\x01\xaf\x68\x5a\xf2\x10\x06\x7c\x5f\x88\xb6\xde\xfe\xfa\xaf\xdd\x0b\xaa\xc5\xf5\x8d\xf9\x03\x15\xec\xc0\xae\xb6\x20\x58\x61\x0e\xdf\x56\x03\x77\xcc\x29\xf5\x0f\x11\xbb\xd0\xe7\xde\x73\xfe\x08\x2f\xa9\x67\xe7\x2c\x58\x9a\x94\x21\x40\x7c\xb0\x63\x1c\xe1\x72\x05\x00\x8a\xef\x01\xe7\xc2\x6b\x2c";static uint8_t ciphertext[] = "\xce\x51\x6b\x4f\xa7\x67\xed\x02\xb6\x1b\x10\x8b\x95\x28\xae\x89";
}








unsigned char prov_key_be_modulus[] = {0xe4, 0x38, 0x44, 0x0a, 0xe6, 0xbb, 0x76, 0x45, 0xd1, 0xe8, 0x4e, 0xf6, 0x01, 0x86, 0x43, 0xac, 0x86, 0xf1, 0x8c, 0xc9, 0x8b, 0x9d, 0x8e, 0xea, 0x1a, 0xd7, 0x68, 0xd6, 0xfe, 0xee, 0x7c, 0x3d, 0x2c, 0x5c, 0xed, 0x26, 0x60, 0xe6, 0x32, 0xba, 0x08, 0xda, 0x03, 0x02, 0xe2, 0x33, 0xb3, 0x55, 0x5f, 0xe9, 0x41, 0x26, 0x61, 0xb6, 0x3c, 0x25, 0x03, 0xe4, 0x29, 0xb9, 0x62, 0x77, 0xab, 0x20, 0x8f, 0x77, 0x63, 0x38, 0x73, 0xe4, 0xfc, 0x15, 0xd5, 0xa0, 0x97, 0x2d, 0x1c, 0x51, 0x46, 0xd8, 0x2a, 0x33, 0x7e, 0xcc, 0x7e, 0x1e, 0x7b, 0x8b, 0x8e, 0x33, 0xc6, 0x20, 0x0c, 0x71, 0x76, 0x8f, 0x5b, 0x52, 0x48, 0xe8, 0xa9, 0x94, 0xd7, 0xb4, 0xd2, 0x0e, 0x13, 0x5c, 0x64, 0x8a, 0xc0, 0x66, 0x90, 0x0a, 0xd3, 0xa9, 0x69, 0x1b, 0xb3, 0x13, 0xd9, 0xaa, 0xfe, 0xc1, 0xc3, 0x7f, 0x84, 0xbe, 0xd7, 0x8f, 0xdf, 0xd1, 0x71, 0xc4, 0xaa, 0x19, 0x83, 0x0e, 0x5b, 0x03, 0xfb, 0x86, 0x2e, 0x61, 0x2a, 0xb3, 0x2d, 0x18, 0x9c, 0x0b, 0xcb, 0xb1, 0x51, 0x48, 0xcd, 0xd9, 0x0f, 0x37, 0x34, 0xb7, 0xf2, 0x8f, 0x7a, 0x4d, 0x43, 0x24, 0x97, 0x0d, 0x6a, 0xb4, 0xd1, 0xd7, 0xdf, 0x57, 0x50, 0xf5, 0xd2, 0xc4, 0x64, 0x44, 0xa5, 0xe0, 0x81, 0x5c, 0xae, 0xf3, 0x76, 0x57, 0x87, 0x70, 0x4a, 0xac, 0x53, 0x50, 0x59, 0xb9, 0x7f, 0x29, 0x3b, 0x2a, 0x37, 0xfd, 0x67, 0x3c, 0xcc, 0x41, 0x2c, 0x4a, 0x42, 0x8d, 0x36, 0xf3, 0xe9, 0x2a, 0x86, 0xd1, 0xb8, 0x30, 0xf6, 0xb7, 0x53, 0x5c, 0x22, 0xf4, 0x35, 0x64, 0x9c, 0x66, 0x9d, 0x16, 0xb7, 0xec, 0x2e, 0xa9, 0x2f, 0x06, 0xb6, 0x55, 0x13, 0x97, 0xc5, 0x48, 0x19, 0x3e, 0x61, 0x93, 0x65, 0xd0, 0xc5, 0x22, 0xab, 0x4b, 0x5b, 0x0f, 0x67, 0x4c, 0xe3, 0xf5, 0xb2, 0x70, 0xc5, 0x57, 0x67, 0x33, 0xa1, 0x4f, 0x6e, 0x1f, 0x25, 0xdc, 0xb9, 0x95, 0x7d, 0x39, 0xbb, 0xa6, 0x03, 0x8e, 0x67, 0x2e, 0xf0, 0xb9, 0x3e, 0x95, 0x47, 0x4f, 0xdc, 0x85, 0xf3, 0xfd, 0x67, 0x72, 0x1a, 0x97, 0xe8, 0x4b, 0xa5, 0x53, 0x29, 0x1d, 0x9d, 0xd0, 0x3f, 0xeb, 0xdc, 0xcf, 0x51, 0x64, 0x68, 0xc6, 0xb6, 0x3f, 0xbc, 0xa5, 0x57, 0x87, 0xd9, 0x29, 0x0c, 0x2a, 0x04, 0x8e, 0x45, 0x56, 0xda, 0x8f, 0xed, 0x6b, 0x89, 0x42, 0x8c, 0xdf, 0xcc, 0x2f, 0x73, 0xad, 0xa0, 0x42, 0x5b, 0xca, 0x51, 0x54, 0x44, 0xc0, 0x9e, 0xd9, 0xf4, 0x9a, 0xc1, 0x43, 0x17, 0x31, 0x58, 0x8b, 0x30, 0xf8, 0x0e, 0xf4, 0xd6, 0xf6, 0x1f, 0x11, 0x35, 0xcf, 0xdf, 0x77, 0x5b, 0xd4, 0xcf, 0x8f, 0x7e, 0x1a, 0x26, 0x86, 0x76, 0xcd, 0x79, 0xc0, 0x4f, 0xb6, 0x31, 0xd6, 0xb1, 0x21};unsigned char prov_key_be_exponent[] = { 0x00, 0x01, 0x00, 0x01};





int connect_to_prov_server() {
	char *hostname = "127.0.0.1";
	int port = 7777;
	return connect_to_server(hostname, port);
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    /* Initialize the enclave */
    /*if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }*/

    uint32_t msg_size = estimate_msg1_size(false);

    pve_data_t pve_data;

    pve_data.is_backup_retrieval = false;
    pve_data.is_performance_rekey = false;

    uint8_t *msg = (uint8_t *)malloc(msg_size);

    if (msg == NULL) {
	printf("msg1: Out of Memory\n");
	return -1;
    }

    memset(msg, 0, msg_size);
    memcpy(&pve_data.pek.n, prov_key_be_modulus, sizeof(pve_data.pek.n)); // 384 byte modulus
    memcpy(&pve_data.pek.e, prov_key_be_exponent, sizeof(pve_data.pek.e)); // 4 bytes exponent

    int ret = bellerophon_gen_prov_msg1(pve_data, msg, msg_size);
    if (ret != AE_SUCCESS) {
	    printf("Gen prov msg1 ret: %d\n", ret);
	    return -1;
    }

    // Connect to the server
    int fd = connect_to_prov_server();
    if (fd < 0) {
	    printf("Connection to server failed\n");
	    return -1;
    }

    //pve_data_t pve_data;

    // Read in the public key from array into pek
    

    /*
    int retval = -1;
    int status = init_hibe(global_eid, &retval, HIBE_DEPTH);

    printf("init_hibe returned: %d, with status: %d\n", retval, status);

    char *hibe_keys[] = { (char *)ciphertext, 0x0 };
   char *encapsulated_keys[] = { (char *)encapsulated_key, 0x0 };
   char *old_identity[] = { "com", "example", "hibe", 0x0};
   char *new_identity[] = { "com", "nonexample", "hibe", 0x0};
   char *re_encrypted_key = (char *)malloc(16);
   char *re_encrypted_keys[] = { re_encrypted_key, 0x0};
   char out_buf[100];

   printf("strlen old_identity[1]: %d\n", strlen(old_identity[1]));
   auto start1 = std::chrono::high_resolution_clock::now();
   //status = reEncryptHIBEWrappedKeys(global_eid, &retval, hibe_keys, 1, encapsulated_keys, old_identity, 1, new_identity, 1, re_encrypted_keys);
   status = re_encrypt_wrapped_hibe_keys_string_depth(global_eid, &retval, HIBE_DEPTH, 1, (char *)ciphertext, 16, (char *)encapsulated_key, out_buf);
   auto end1 = std::chrono::high_resolution_clock::now();
   printf("reEncryptHIBEWrappedKeys returned: %d, with status: %d\n", retval, status);*/
   
    
    /* Utilize edger8r attributes */
    //edger8r_array_attributes();
    //edger8r_pointer_attributes();
    //edger8r_type_attributes();
    //edger8r_function_attributes();
    
    /* Utilize trusted libraries */
    //ecall_libc_functions();
    //ecall_libcxx_functions();
    //ecall_thread_functions();
    

    /* Destroy the enclave */
    //sgx_destroy_enclave(global_eid);

    //std::chrono::duration<double> elapsed = end1 - start1;
    
    //printf("Info: SampleEnclave successfully returned.\n");
    //std::cout << "reEncryption Elapsed time: " << elapsed.count() << " s\n";

    //printf("Enter a character before exit ...\n");
    //getchar();
    return 0;
}

