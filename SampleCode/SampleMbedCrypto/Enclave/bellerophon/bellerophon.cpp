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
    uint32_t secret_data;

    target_fn_id = 0;
    msg_type = MESSAGE_EXCHANGE;
    max_out_buff_size = 50; // it's assumed the maximum payload size in response message is 50 bytes, it's for demonstration purpose
    secret_data = 0x12345678; //Secret Data here is shown only for purpose of demonstration.

    //Marshals the secret data into a buffer
    ke_status = marshal_message_exchange_request(target_fn_id, msg_type, secret_data, &marshalled_inp_buff, &marshalled_inp_buff_len);
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
    ke_status = umarshal_message_exchange_response(out_buff, &secret_response);
    if(ke_status != SUCCESS)
    {
        SAFE_FREE(marshalled_inp_buff);
        SAFE_FREE(out_buff);
        return ke_status;
    }

    SAFE_FREE(marshalled_inp_buff);
    SAFE_FREE(out_buff);

    return 0;

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

   uint8_t key[16] = {0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa };
   ret = get_decryption_key(&g_session,(uint8_t *)&key, 16);
   if (ret != 0) {
	   ocall_print_string("Error getting decryption key\n");
           return ret;
   }

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

