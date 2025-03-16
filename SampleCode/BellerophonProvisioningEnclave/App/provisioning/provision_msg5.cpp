#include "type_length_value.h"
#include "epid_utility.h"
#include "oal/oal.h"
#include "aeerror.h"
#include "PVEClass.h"
#include "pce_service.h"
#include "aesm_rand.h"
#include "epid_pve_type.h"
#include "crypto_wrapper.h"
#include "pce_bellerophon.h"
#include "sgx_read_rand.h"
#include "provision_enclave.h"
#include <memory>

static ae_error_t gen_msg5_header(provision_request_header_t *header, uint32_t payload_size, const uint8_t xid[XID_SIZE]) {
	header->protocol = SE_EPID_PROVISIONING;

	header->version = TLV_VERSION_2;
   	header->type = TYPE_PROV_MSG3;

	if(0!=memcpy_s(header->xid, sizeof(header->xid), xid, XID_SIZE))
		return PVE_UNEXPECTED_ERROR; //copy transaction id of ProvMsg2
	uint32_t size_in_net = _htonl(payload_size);
	if(0!=memcpy_s(&header->size, sizeof(header->size), &size_in_net, sizeof(size_in_net)))
        	return PVE_UNEXPECTED_ERROR;//size in Big Endian in message header of ProvMsg3

	return AE_SUCCESS;
}


uint32_t bellerophon_gen_prov_msg5(pve_data_t &pve_data, uint8_t *n_be, uint32_t n_size, uint8_t *e_be, uint32_t e_size, uint8_t *d_be, uint32_t d_size,
		uint8_t *msg4, uint32_t msg4_size, uint8_t **msg5, uint32_t *msg5_size) {
	/// Deserializing the TLVs from the message
	if (msg4_size <= 0)
		return 1;
	if (msg4 == NULL)
		return 2;

	provision_response_header_t *header = (provision_response_header_t *)msg4;
	uint8_t *tlv_start = (uint8_t *)(msg4 + sizeof(provision_response_header_t));
	uint32_t tlvs_size = msg4_size - sizeof(provision_response_header_t);

	TLVsMsg tlvs_msg4;
	tlv_status_t ret = tlvs_msg4.init_from_buffer(tlv_start, tlvs_size);
	if (ret != TLV_SUCCESS) {
		return 3;
	}

	tlv_info_t& enc_payload = tlvs_msg4[0];
	tlv_info_t& iv = tlvs_msg4[1];

	printf("[msg4] enc_payload->size: %u\niv->size: %u\n", enc_payload.size, iv.size); 
	uint8_t *ciphertext = enc_payload.payload;
	uint32_t ciphertext_len = enc_payload.size;
	//uint8_t *tag = (uint8_t *)(ciphertext + 8);
	//uint32_t tag_len = 16;
	uint8_t *iv_buf = iv.payload;
	uint32_t iv_size = iv.size;
	
	printf("[msg4] ciphertext: ");
        for (int i = 0; i < enc_payload.size; i++) {
                unsigned char c = ((unsigned char *)ciphertext)[i];
                printf("%u ", (unsigned int)c);
        }
	printf("\n");

	printf("[msg4] iv: ");
        for (int i = 0; i < iv_size; i++) {
                unsigned char c = ((unsigned char *)iv_buf)[i];
                printf("%u ", (unsigned int)c);
        }

	printf("\n");

	// Reconstruct rsa private key
	uint8_t little_n[384];
	uint8_t little_e[4];
	uint8_t little_d[384];
	

	uint32_t i;
    	for(i = 0; i < sizeof(little_n); i++) {
        	little_n[i] = n_be[sizeof(little_n)-1-i];
    	}

    	for(i = 0; i < sizeof(little_e); i++) {
        	little_e[i] = e_be[sizeof(little_e)-1-i];
    	}

	for(i = 0; i < sizeof(little_d); i++) {
		little_d[i] = d_be[sizeof(little_d)-1-i];
	}

	void *rsa_pvt_key = NULL;
	sgx_status_t priv_key_ret = sgx_create_rsa_priv1_key(384, 4, 384, (const unsigned char *)little_n, (const unsigned char *)little_e, 
			(const unsigned char *)little_d, &rsa_pvt_key);
	
	if (priv_key_ret != SGX_SUCCESS)
		return 4;

	size_t output_size;
	sgx_status_t rsa_decrypt_ret = sgx_rsa_priv_decrypt_sha256(rsa_pvt_key, NULL, &output_size, ciphertext, ciphertext_len);
	if (rsa_decrypt_ret != SGX_SUCCESS)
		return 5;
	
	uint8_t *decrypted_challenge = (uint8_t *)malloc(output_size);
	rsa_decrypt_ret = sgx_rsa_priv_decrypt_sha256(rsa_pvt_key, decrypted_challenge, &output_size, ciphertext, ciphertext_len);
	if (rsa_decrypt_ret != SGX_SUCCESS)
		return 6;

	printf("[msg5] decrypted_challenge: ");
	for (int i = 0; i < output_size; i++) {
                unsigned char c = ((unsigned char *)decrypted_challenge)[i];
                printf("%u ", (unsigned int)c);
        }
	printf("\n");
	
	TLVsMsg tlvs_msg5;
	tlvs_msg5.add_data(decrypted_challenge, output_size, TLV_NONCE);

	uint8_t *msg5_buf = (uint8_t *)malloc(tlvs_msg5.get_tlv_msg_size() + sizeof(provision_request_header_t));
        if (gen_msg5_header(reinterpret_cast<provision_request_header_t *>(msg5_buf), tlvs_msg5.get_tlv_msg_size(), pve_data.xid) != AE_SUCCESS) {
                return 5;
        }

        memcpy(msg5_buf + sizeof(provision_request_header_t), tlvs_msg5.get_tlv_msg(), tlvs_msg5.get_tlv_msg_size());

        *msg5 = msg5_buf;
        *msg5_size = tlvs_msg5.get_tlv_msg_size() + sizeof(provision_request_header_t);

	return 0;
}

