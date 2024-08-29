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

char encapsulated_key[] = "\x88\x51\x21\xac\x5b\x7b\x48\x4f\xf9\xbe\x1a\xed\xbd\x21\xa9\xd7\x59\xb4\x4e\x5f\x69\x42\xad\x9d\x55\x56\xe9\x9c\xe6\xfc\x8f\xd0\xaf\xa8\x2a\x94\xe9\x33\x95\x54\x54\xf6\xdd\x8d\xc8\x56\x1c\x09\x2a\x21\x7b\x30\xe4\x26\x84\xa1\x92\x05\x94\xf4\xec\x69\xb8\xf3\xb6\x2d\x63\x0c\x89\xc2\x7d\x08\x60\xb2\xe8\xa1\xc9\x51\xab\x40\x1e\x44\xb3\xcd\x95\xfe\x6c\x3f\x9e\xee\xc2\x0c\xce\x99\x89\x0c\x00\xb1\xd0\xbd\x0d\x5d\x34\xbd\x0c\x0d\xef\xe9\xe3\xc3\xcf\x75\x0e\x4b\x3e\x59\x57\x6d\x12\x2d\x5a\x50\x1d\xcd\xb4\x0c\x64\x75\xa4\xe5\x11\x65\x9e\x3e\x60\x87\x54\x75\xb5\x90\x86\xfa\xed\xe4\xa5\x75\xad\xc2\x87\xfe\x22\x03\x15\xd0\x4f\x89\x26\x91\xb0\xb7\x9b\xc3\xc3\xaf\x07\x2d\xa7\x87\xca\x8a\x95\xfe\x8f\x30\xce\x74\xd2\x06\x6a\x01\x4d\xe6\xe3\x18\x43\xee\x1c\xce\x5d\xe4\xb6\x3f\xf4\x46\xe6\x3b\xe2\x21\xc8\x00\xe7\xd6\xef\x00\xed\xf8\xd6\xd4\x33\xde\x8e\x45\x33\xc6\xc0\x99\xf9\x36\x24\xeb\x14\x10\x29\x54\xa1\xde\xed\x93\xa0\x30\xed\x0d\x48\xc6\x12\xc4\xba\x8e\xed\x02\xd7\x64\x37\xc4\xfe\xa4\x94\x10\xeb\xa4\x99\x67\xc9\x91\x6c\xff\x38\x4f\x22\x8e\x35\x48\x76\xe8\xdc\x14\x0b\x5e\x85\x4f\xdb\xd0\x2d\xec\xc3\xee\x63\xba\x92\x03\x7a\x0f\xa3\x56\x50\xdd\xe4\x8b\xf2\x18\x11\xa9\xa5\x47\x15\x03\x00\xd4\x99\xc7\xc6\x64\x21\x73";
char ciphertext[] = "\x19\x2d\x7e\x0d\xcb\xa9\xd1\xf2\xac\x11\x0b\xc0\xee\x90\x32\x17";

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
    int status = init_hibe(global_eid, &retval);

    printf("init_hibe returned: %d, with status: %d\n", retval, status);

   char *hibe_keys[] = { ciphertext, 0x0 };
   char *encapsulated_keys[] = { encapsulated_key, 0x0 };
   char *old_identity[] = { "com", "example", "hibe", 0x0};
   char *new_identity[] = { "com", "nonexample", "hibe", 0x0};
   char *re_encrypted_key = (char *)malloc(16);
   char *re_encrypted_keys[] = { re_encrypted_key, 0x0};

   printf("strlen old_identity[1]: %d\n", strlen(old_identity[1]));
   auto start1 = std::chrono::high_resolution_clock::now();
   status = reEncryptHIBEWrappedKeys(global_eid, &retval, hibe_keys, 1, encapsulated_keys, old_identity, 1, new_identity, 1, re_encrypted_keys);
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

