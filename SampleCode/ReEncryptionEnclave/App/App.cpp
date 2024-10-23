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
#include "Enclave_u.h"

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

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}


static uint8_t encapsulated_key[] = "\xbb\xec\xc4\x55\x84\xa8\x10\x97\xbb\x9c\x1d\xd1\xd9\x2e\xf5\x7f\x1e\xc0\x86\x27\xa2\xbb\x3a\x24\x77\x15\x8e\x34\x88\x54\xeb\xf9\xee\x1a\x9e\x21\x3c\xa8\xc1\xd7\xc8\x7a\x8a\xc7\x36\x80\x0a\x07\x59\x8a\xef\x01\xe7\xc2\x6b\x2c\xa5\x5d\x2d\xac\x5d\x76\xb1\x5e\x9e\x0e\x1e\x90\xf9\x36\x40\xca\xcc\x0a\xf8\x17\x99\xdd\x42\xa8\x1a\x57\xaf\x83\x1e\xd2\x5e\x7d\x9c\xd2\x39\x33\x81\x1d\x6e\x11\x00\xc5\xf5\x8d\xf9\x03\x15\xec\x15\xa7\x76\xa4\xed\x23\x22\xd2\xc7\xcf\x54\x34\x37\x9c\xe5\x45\x13\x66\x4a\xc5\x32\x8c\xf1\x42\xf8\x81\x84\xda\x12\x18\xdd\xd1\x4f\x66\x55\x81\xcd\x57\xfc\xc5\xba\x36\xdc\x84\xe5\xe8\x53\x05\xb6\x3e\x14\xb4\xb4\xa8\x75\x45\x29\x96\xbc\xae\xc9\x3e\x4e\x8b\xf8\x18\xcd\x3d\x0c\x3b\xdc\x8c\x62\x2a\x4b\xf1\xee\x6f\xd6\x4c\xdd\x0f\xcb\x15\x86\xa5\x40\xc0\x22\xaf\x87\xac\xea\x19\xee\x12\xf2\x54\x1b\xc8\xe2\xe3\xea\x82\x62\xaa\x5c\x0b\xeb\x62\xc1\x4b\x66\x1d\xaf\x18\xea\x50\x33\xb0\x82\x7e\x2c\x63\x31\x82\x92\x01\xaf\x68\x5a\xf2\x10\x06\x7c\x5f\x88\xb6\xde\xfe\xfa\xaf\xdd\x0b\xaa\xc5\xf5\x8d\xf9\x03\x15\xec\xc0\xae\xb6\x20\x58\x61\x0e\xdf\x56\x03\x77\xcc\x29\xf5\x0f\x11\xbb\xd0\xe7\xde\x73\xfe\x08\x2f\xa9\x67\xe7\x2c\x58\x9a\x94\x21\x40\x7c\xb0\x63\x1c\xe1\x72\x05\x00\x8a\xef\x01\xe7\xc2\x6b\x2c";static uint8_t ciphertext[] = "\xce\x51\x6b\x4f\xa7\x67\xed\x02\xb6\x1b\x10\x8b\x95\x28\xae\x89";


/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);


    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }


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
   printf("reEncryptHIBEWrappedKeys returned: %d, with status: %d\n", retval, status);
 
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
    sgx_destroy_enclave(global_eid);

    std::chrono::duration<double> elapsed = end1 - start1;
    
    printf("Info: SampleEnclave successfully returned.\n");
    std::cout << "reEncryption Elapsed time: " << elapsed.count() << " s\n";

    //printf("Enter a character before exit ...\n");
    //getchar();
    return 0;
}

