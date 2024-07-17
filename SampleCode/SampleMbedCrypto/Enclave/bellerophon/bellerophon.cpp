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

static uint8_t ciphertext[] = "\xa3\xf7\x82\xf3\x82\x91\x4e\x53\x7b\x32\x73\x37\x26\xd5\xf6\xc9";
static uint8_t encapsulated_key[] = "\xba\x55\x11\xde\x7a\x54\x65\x7c\x3a\xf3\xcf\xad\x62\x85\xae\x3a\x53\xee\x19\x76\xe2\xac\xd5\x5f\xf8\xc1\x94\x6e\xa\x1f\x33\x29\xd9\xd9\x96\x55\x53\x2b\xcb\xd1\x6\xb2\x67\xc9\xb8\x3f\x38\xa\xd8\xc5\xa9\xe8\x92\x4e\x48\xbf\xcd\x18\x71\x58\x93\xa4\xf5\x2\x49\x3b\x6\x81\x1d\x3e\xb5\x9\x1c\x20\x53\x53\x69\x37\xfc\x70\xe2\xb8\xf6\x9e\x72\xa2\xc\xf0\x30\x1f\xa9\x2\x63\xd7\x34\x2\x0\xe1\x50\xd2\xae\x1f\x72\x29\x7\x6d\x19\xde\xb1\xa8\x69\xb6\xf\xdd\x11\x62\xb7\x17\x51\xa\x5f\x52\x70\x57\x24\x49\xa8\x3\x79\xc8\xdb\x5c\x80\x59\x32\xb7\xa9\xb4\xa\x1\x9\x6e\x5d\x1e\xf0\x64\x44\x6e\x2f\x3d\x7\xe\x43\x38\x18\xb5\x4\x4f\x72\xde\x36\xca\x63\xcb\x16\x4a\xbc\x96\x96\x1\x7c\xa3\x79\xa4\xbb\xba\xe6\x5e\x5e\x14\xd7\xe\xa5\x6\x24\xc0\x94\xdb\xba\xb8\x74\x7f\xe\xdd\x2b\xfd\xad\x72\x49\x15\x8e\xeb\x8d\xac\xa3\xe6\xd2\x2\xbb\x1d\x51\x13\x7c\x38\xe9\x59\xe5\x91\x58\xa7\x39\x24\x87\x1b\x7f\xa1\x48\x45\x73\xd5\x76\xa9\x1a\xc7\xbe\xdd\xec\xfb\x56\x8c\x43\x79\x5\x34\xa3\x72\xbc\x12\xde\xd7\xc6\x80\xa1\x8e\x2c\xec\xa7\xad\x89\xc8\xb\xa4\x65\xac\xa\x97\xf3\xd6\x1\x4d\xf7\x43\x45\x12\xee\xcb\xff\x2c\xe3\xfb\x2\x8a\x28\x76\xfe\x66\xc1\x8e\xe0\x7f\x8b\x25\x8e\x28\x3b\x1\x0\x15\x5c\x15\x69\x98\x44\x48";

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
    max_out_buff_size = 50; // it's assumed the maximum payload size in response message is 50 bytes, it's for demonstration purpose
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

    //Core Reference Code function
    ke_status = send_request_receive_response(session, marshalled_inp_buff,
                                                marshalled_inp_buff_len, max_out_buff_size, &out_buff, &out_buff_len);
    if(ke_status != SUCCESS)
    {
        SAFE_FREE(marshalled_inp_buff);
        SAFE_FREE(out_buff);
        return ke_status;
    }

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

   //uint8_t key1[16] = {0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa };
   uint8_t key1[16] = { 0x0 };
   ret = get_decryption_key(&g_session,(uint8_t *)&key1, 16);
   if (ret != 0) {
	   ocall_print_string("Error getting decryption key\n");
           return ret;
   }

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

