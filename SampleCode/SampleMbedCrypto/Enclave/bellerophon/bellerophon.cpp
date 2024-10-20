#include <stdint.h>
#include "bellerophon_tbl.h"
#include "../Enclave_t.h"

#include "sgx_eid.h"
//#include "EnclaveInitiator_t.h"
#include "EnclaveMessageExchange.h"
#include "error_codes.h"
#include "Utility_E1.h"
#include "sgx_dh.h"
#include "sgx_utils.h"
#include <map>

#define RESPONDER_PRODID 1

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

//extern "C" char *setup_hibe(int32_t depth, char *seed_buf, int32_t seed_size, int32_t *out_size);

extern "C" uint8_t dummy_func() {
	return 0;
}

extern "C" uint32_t verify_peer_enclave_trust(sgx_dh_session_enclave_identity_t* peer_enclave_identity)
{
    if (!peer_enclave_identity)
        return INVALID_PARAMETER_ERROR;

    // check peer enclave's MRSIGNER
    // Please enable blow check in your own project!!!
    /*
    if (memcmp((uint8_t *)&peer_enclave_identity->mr_signer, (uint8_t*)&g_responder_mrsigner, sizeof(sgx_measurement_t)))
        return ENCLAVE_TRUST_ERROR;
    */
    // check peer enclave's product ID and enclave attribute (should be INITIALIZED'ed)
    if (peer_enclave_identity->isv_prod_id != RESPONDER_PRODID || !(peer_enclave_identity->attributes.flags & SGX_FLAGS_INITTED))
        return ENCLAVE_TRUST_ERROR;

    // check the enclave isn't loaded in enclave debug mode, except that the project is built for debug purpose
#if defined(NDEBUG)
    if (peer_enclave_identity->attributes.flags & SGX_FLAGS_DEBUG)
        return ENCLAVE_TRUST_ERROR;
#endif

    return SUCCESS;
}

static uint8_t encapsulated_key[] = "\xbb\xec\xc4\x55\x84\xa8\x10\x97\xbb\x9c\x1d\xd1\xd9\x2e\xf5\x7f\x1e\xc0\x86\x27\xa2\xbb\x3a\x24\x77\x15\x8e\x34\x88\x54\xeb\xf9\xee\x1a\x9e\x21\x3c\xa8\xc1\xd7\xc8\x7a\x8a\xc7\x36\x80\x0a\x07\x59\x8a\xef\x01\xe7\xc2\x6b\x2c\xa5\x5d\x2d\xac\x5d\x76\xb1\x5e\x9e\x0e\x1e\x90\xf9\x36\x40\xca\xcc\x0a\xf8\x17\x99\xdd\x42\xa8\x1a\x57\xaf\x83\x1e\xd2\x5e\x7d\x9c\xd2\x39\x33\x81\x1d\x6e\x11\x00\xc5\xf5\x8d\xf9\x03\x15\xec\x15\xa7\x76\xa4\xed\x23\x22\xd2\xc7\xcf\x54\x34\x37\x9c\xe5\x45\x13\x66\x4a\xc5\x32\x8c\xf1\x42\xf8\x81\x84\xda\x12\x18\xdd\xd1\x4f\x66\x55\x81\xcd\x57\xfc\xc5\xba\x36\xdc\x84\xe5\xe8\x53\x05\xb6\x3e\x14\xb4\xb4\xa8\x75\x45\x29\x96\xbc\xae\xc9\x3e\x4e\x8b\xf8\x18\xcd\x3d\x0c\x3b\xdc\x8c\x62\x2a\x4b\xf1\xee\x6f\xd6\x4c\xdd\x0f\xcb\x15\x86\xa5\x40\xc0\x22\xaf\x87\xac\xea\x19\xee\x12\xf2\x54\x1b\xc8\xe2\xe3\xea\x82\x62\xaa\x5c\x0b\xeb\x62\xc1\x4b\x66\x1d\xaf\x18\xea\x50\x33\xb0\x82\x7e\x2c\x63\x31\x82\x92\x01\xaf\x68\x5a\xf2\x10\x06\x7c\x5f\x88\xb6\xde\xfe\xfa\xaf\xdd\x0b\xaa\xc5\xf5\x8d\xf9\x03\x15\xec\xc0\xae\xb6\x20\x58\x61\x0e\xdf\x56\x03\x77\xcc\x29\xf5\x0f\x11\xbb\xd0\xe7\xde\x73\xfe\x08\x2f\xa9\x67\xe7\x2c\x58\x9a\x94\x21\x40\x7c\xb0\x63\x1c\xe1\x72\x05\x00\x8a\xef\x01\xe7\xc2\x6b\x2c";static uint8_t ciphertext[] = "\xce\x51\x6b\x4f\xa7\x67\xed\x02\xb6\x1b\x10\x8b\x95\x28\xae\x89";

static size_t ciphertext_len = 16;
static size_t encapsulated_key_len = 304;

static int get_decryption_key(dh_session_t *session, uint8_t *key, int key_len) __attribute__((section(".decrypt_stub")));

static int get_decryption_key(dh_session_t *session, uint8_t *key, int key_len)
{
    ATTESTATION_STATUS ke_status = SUCCESS;
    uint32_t target_fn_id, msg_type;
    char* marshalled_inp_buff;
    size_t marshalled_inp_buff_len;
    char* out_buff;
    size_t out_buff_len;
    size_t max_out_buff_size;
    char* secret_response;
    //uint32_t secret_data;

    target_fn_id = 0;
    msg_type = DECRYPTION_REQUEST;
    max_out_buff_size = 4096; // it's assumed the maximum payload size in response message is 50 bytes, it's for demonstration purpose
    //secret_data = 0x12345678; //Secret Data here is shown only for purpose of demonstration.

    decryption_request_t dec_req;
    memcpy(&(dec_req.enc_key), ciphertext, ciphertext_len);
    dec_req.enc_key_size = ciphertext_len;
    memcpy(&(dec_req.encapsulated_key), encapsulated_key, encapsulated_key_len);
    dec_req.encapsulated_key_size = encapsulated_key_len;

    //Marshals the secret data into a buffer
    //ke_status = marshal_message_exchange_request(target_fn_id, msg_type, secret_data, &marshalled_inp_buff, &marshalled_inp_buff_len);
    ke_status = bellerophon_marshal_message_exchange_request(target_fn_id, msg_type, (uint8_t *)&dec_req, sizeof(decryption_request_t), &marshalled_inp_buff, &marshalled_inp_buff_len);  
    if(ke_status != SUCCESS)
    {
        return ke_status;
    }
    //ocall_print_string("Here1\n");

    //Core Reference Code function
    ke_status = send_request_receive_response(session, marshalled_inp_buff,
                                                marshalled_inp_buff_len, max_out_buff_size, &out_buff, &out_buff_len);
    if(ke_status != SUCCESS)
    {
        SAFE_FREE(marshalled_inp_buff);
        SAFE_FREE(out_buff);
        return ke_status;
    }

    //ocall_print_string("Here2\n");

    //Un-marshal the secret response data
    //ke_status = umarshal_message_exchange_response(out_buff, &secret_response);
    size_t secret_len;
    ke_status = bellerophon_umarshal_message_exchange_response(out_buff, &secret_response, &secret_len);
    if(ke_status != SUCCESS)
    {
        SAFE_FREE(marshalled_inp_buff);
        SAFE_FREE(out_buff);
        return ke_status;
    }

    //ocall_print_string("Here3\n");

    memcpy(key, secret_response, secret_len);

    SAFE_FREE(marshalled_inp_buff);
    SAFE_FREE(out_buff);

    return SUCCESS;

}


extern "C" int decrypt_enclave(int decrypt)
{
   if (decrypt == 0) {
	   ocall_print_string("Hello from enclave :-)\n");
	   return 0;
   }

   int ret = 0;

   dh_session_t g_session;

   ret = create_session(&g_session);
   if (ret != 0) {
	   ocall_print_string("Error creating session\n");
	   return ret;
   }

   //ocall_print_string("After creating DH session\n");

   //uint8_t key1[16] = {0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa };
   uint8_t key1[16] = { 0x0 };
   ret = get_decryption_key(&g_session,(uint8_t *)&key1, 16);
   if (ret != 0) {
	   ocall_print_string("Error getting decryption key\n");
           return ret;
   }

   //ocall_print_string("After getting decryption key");

   uint8_t key[16] = {0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa };
   if (memcmp(key1, key, 16) != 0) {
	   ocall_print_string("Error decrypting HIBE key\n");
	   ocall_print_buffer((unsigned char *)key1, 16);
	   return -1;
   }

   //char seed[32] = { 0xa };

   //int32_t hibe_setup_len;
   //char *hibe_setup_keys = setup_hibe(4, (char *)seed, 32, &hibe_setup_len);
   //ocall_print_string("[decrypt_enclave] After setup_hibe\n");

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

