#include <stdint.h>
#include "bellerophon_tbl.h"
#include "../Enclave_t.h"


extern "C" void* get_enclave_base(void);

extern "C" sgx_status_t pcl_gcm_decrypt(
        IN uint8_t* plaintext,
        OUT uint8_t* ciphertext,
        size_t textlen,
        IN uint8_t* aad,
        size_t aad_len,
        IN uint8_t* key,
        IN uint8_t* iv,
        IN uint8_t* tag);

extern "C" int decrypt_enclave(int decrypt) __attribute__((section(".decrypt_stub")));


extern "C" int decrypt_enclave(int decrypt)
{
   if (decrypt == 0) {
	   ocall_print_string("Hello from enclave :-)\n");
	   return 0;
   }

   int ret = 0;

   uint8_t key[16] = {0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa };
   pcl_table_t *tbl = &g_bellerophon_tbl;
   tbl->pcl_state = PCL_PLAIN;

   uint32_t num_rvas = tbl->num_rvas;
   size_t decrypt_stub_section_rva = tbl->rvas_sizes_tags_ivs[num_rvas + 1].rva;
   uint64_t elf_base = (uint64_t)get_enclave_base();

   for (uint32_t i = 0; i < num_rvas; i++) {
	size_t size = tbl->rvas_sizes_tags_ivs[i].size;
        unsigned char* ciphertext = (unsigned char *)((uint64_t)elf_base + tbl->rvas_sizes_tags_ivs[i].rva);
        unsigned char* plaintext = ciphertext; // decrypt in place
        unsigned char* tag = (unsigned char *)&(tbl->rvas_sizes_tags_ivs[i].tag);
        unsigned char* iv  = (unsigned char *)&(tbl->rvas_sizes_tags_ivs[i].iv.val);

        // Verify ciphertext is inside the enclave:
        /*if(!(pcl_is_within_enclave(ciphertext, size)))
        {
            return SGX_ERROR_UNEXPECTED;
        }*/
        ret = pcl_gcm_decrypt(plaintext, ciphertext, size, NULL, 0, key, iv, tag);
        if(SGX_SUCCESS != ret)
        {
            return ret;
        }
   } 

   return 0;
}

