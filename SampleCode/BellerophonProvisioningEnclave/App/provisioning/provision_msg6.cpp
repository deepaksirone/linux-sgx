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
#include "provision_enclave_u.h"
#include <memory>

#define PROVISION_ENCLAVE_FILENAME "libsgx_pve_bellerophon.signed.so"

static int load_provision_enclave(sgx_enclave_id_t *eid)
{
        sgx_status_t ret = SGX_ERROR_UNEXPECTED;

        /* Call sgx_create_enclave to initialize an enclave instance */
        /* Debug Support: set 2nd parameter to 1 */
        ret = sgx_create_enclave(PROVISION_ENCLAVE_FILENAME, 1, NULL, NULL, eid, NULL);
        if (ret != SGX_SUCCESS) {
                //print_error_message(ret);
                return -1;
        }

        return 0;
}


int bellerophon_proc_msg6(uint8_t *msg6, uint32_t msg6_size) {
	if (msg6_size == 0)
                return 1;
        if (msg6 == NULL)
                return 2;
	
	provision_response_header_t *header = (provision_response_header_t *)msg6;
        uint8_t *tlv_start = (uint8_t *)(msg6 + sizeof(provision_response_header_t));
        uint32_t tlvs_size = msg6_size - sizeof(provision_response_header_t);

	TLVsMsg tlvs_msg6;
        tlv_status_t ret = tlvs_msg6.init_from_buffer(tlv_start, tlvs_size);
        if (ret != TLV_SUCCESS) {
                return 3;
        }

	tlv_info_t& enc_hibe_key = tlvs_msg6[0];
        tlv_info_t& hibe_pubkey = tlvs_msg6[1];
	tlv_info_t& hibe_pubkey_string = tlvs_msg6[2];
	tlv_info_t& iv_tlv = tlvs_msg6[3];

	uint8_t *hibe_pvt_key_payload = enc_hibe_key.payload;
	uint32_t hibe_payload_size = enc_hibe_key.size - 16;
	uint8_t *tag = enc_hibe_key.payload + hibe_payload_size;
	uint32_t tag_len = 16;
	
	sgx_enclave_id_t eid = 0;
        if (load_provision_enclave(&eid)) {
                printf("[bellerophon_proc_msg6.cpp] Failed to load provisioning enclave\n");
                return -1;
        }

	uint32_t retval;
        int r = proc_msg6_data_wrapper(eid, &retval, hibe_pvt_key_payload, hibe_payload_size, tag, tag_len, iv_tlv.payload, iv_tlv.size);

        printf("PvE msg6 ret: %d, retval: %u\n", r, retval);

        sgx_destroy_enclave(eid);

	return r;	
}	
