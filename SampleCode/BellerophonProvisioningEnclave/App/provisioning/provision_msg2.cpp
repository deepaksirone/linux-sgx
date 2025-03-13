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

static ae_error_t gen_msg3_header(provision_request_header_t *header, uint32_t payload_size, const uint8_t xid[XID_SIZE]) {
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


uint32_t bellerophon_gen_prov_msg2(pve_data_t &pve_data, uint8_t *msg, uint32_t msg_size, uint8_t **msg3, uint32_t *msg3_size) {
	/// Deserializing the TLVs from the message
	if (msg_size <= 0)
		return 1;
	if (msg == NULL)
		return 2;

	provision_response_header_t *header = (provision_response_header_t *)msg;
	uint8_t *tlv_start = (uint8_t *)(msg + sizeof(provision_response_header_t));
	uint32_t tlvs_size = msg_size - sizeof(provision_response_header_t);

	TLVsMsg tlvs_msg2;
	tlv_status_t ret = tlvs_msg2.init_from_buffer(tlv_start, tlvs_size);
	if (ret != TLV_SUCCESS) {
		return 3;
	}

	tlv_info_t& enc_payload = tlvs_msg2[0];
	tlv_info_t& iv = tlvs_msg2[1];

	printf("enc_payload->size: %u\niv->size: %u\n", enc_payload.size, iv.size); 
	uint8_t *ciphertext = enc_payload.payload;
	uint32_t ciphertext_len = 8;
	uint8_t *tag = (uint8_t *)(ciphertext + 8);
	uint32_t tag_len = 16;
	uint8_t *iv_buf = iv.payload;
	uint32_t iv_size = iv.size;
	
	printf("ciphertext: ");
        for (int i = 0; i < enc_payload.size; i++) {
                unsigned char c = ((unsigned char *)ciphertext)[i];
                printf("%u ", (unsigned int)c);
        }
	printf("\n");

	printf("iv: ");
        for (int i = 0; i < iv_size; i++) {
                unsigned char c = ((unsigned char *)iv_buf)[i];
                printf("%u ", (unsigned int)c);
        }

	printf("\n");

	uint8_t prov_key[16];
	memset(prov_key, 0xa, 16);

	
	uint8_t *challenge = (uint8_t*)malloc(8);
	/*sgx_status_t r1 = sgx_rijndael128GCM_decrypt(&prov_key, ciphertext, ciphertext_len, (uint8_t *)challenge, iv_buf, iv_size, 
			NULL, 0, (sgx_aes_gcm_128bit_tag_t *)tag);
	printf("Decryption r1: %d\n", r1);

	printf("challenge: ");
	for (int i = 0; i < 8; i++) {
		unsigned char c = ((unsigned char *)challenge)[i];
		printf("%u ", (unsigned int)c);
	}
	printf("\n");*/



	// Get the PvE to decrypt the blob and send it back
	// TODO: Fix this bug; decryption not working inside pve
 	int r = bellerophon_gen_prov_msg2_data(ciphertext, ciphertext_len, tag, tag_len, iv_buf, iv_size, challenge);	
	if (r != 0)
		return 4;

	printf("challenge: ");
	for (int i = 0; i < 8; i++) {
		unsigned char c = ((unsigned char *)challenge)[i];
		printf("%u ", (unsigned int)c);
	}
	printf("\n");

	TLVsMsg tlvs_msg3; 
	tlvs_msg3.add_data(challenge, 8, TLV_NONCE);
	tlvs_msg3.add_data((uint8_t*)&pve_data.pek.n, sizeof(pve_data.pek.n), TLV_PEK);
	tlvs_msg3.add_data((uint8_t*)&pve_data.pek.e, sizeof(pve_data.pek.e), TLV_PEK);
	
	uint8_t *msg3_buf = (uint8_t *)malloc(tlvs_msg3.get_tlv_msg_size() + sizeof(provision_request_header_t));
	if (gen_msg3_header(reinterpret_cast<provision_request_header_t *>(msg3_buf), tlvs_msg3.get_tlv_msg_size(), pve_data.xid) != AE_SUCCESS) {
		return 5;
	}

	memcpy(msg3_buf + sizeof(provision_request_header_t), tlvs_msg3.get_tlv_msg(), tlvs_msg3.get_tlv_msg_size());

	*msg3 = msg3_buf;
	*msg3_size = tlvs_msg3.get_tlv_msg_size() + sizeof(provision_request_header_t);

	return 0;
}

