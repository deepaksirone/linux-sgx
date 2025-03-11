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


uint32_t bellerophon_gen_prov_msg2(uint8_t *msg, uint32_t msg_size, uint8_t **msg3, uint32_t *msg3_size) {
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

	return 0;
}

