#include "sgx_urts.h"
//#include "../../Enclave/Enclave.h"
//#include "../Enclave_u.h"
#include "provision_enclave_u.h"
#include <cstdlib>
#include <cstdio>

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

static int read_epid_blob(extended_epid_group_blob_t& blob) {
	char *blob_filepath = std::getenv("EPID_BLOB_PATH");
	if (!blob_filepath)
		return -1;

	FILE *blob_file = fopen(PROVISION_ENCLAVE_FILENAME, "rb");
	uint8_t *buf = reinterpret_cast<uint8_t *>(&blob);
	uint32_t buf_size = (uint32_t)fread(buf, 1, sizeof(extended_epid_group_blob_t), blob_file);
	
	return buf_size;
}


int bellerophon_gen_prov_msg1_data(const signed_pek_t* pek, const sgx_target_info_t* pce_target_info, sgx_report_t* msg1_output) {
	sgx_enclave_id_t eid = 0;
	if (load_provision_enclave(&eid)) {
		printf("[provision_enclave.cpp] Failed to load provisioning enclave\n");
		return -1;
	}

	extended_epid_group_blob_t xegb;

	if (read_epid_blob(xegb) < 0) {
		printf("[provision_enclave.cpp] Failed to load EPID Blob\n");
		return -2;
	}
	
	uint32_t retval;
	//int ret = bellerophon_gen_prov_msg1_data_wrapper(eid, &retval, pek, pce_target_info, msg1_output);
	int ret = gen_prov_msg1_data_wrapper(eid, &retval, &xegb, pek, pce_target_info, msg1_output);

	printf("PvE ret: %d, retval: %u\n", ret, retval);

	sgx_destroy_enclave(eid);

	return ret;
}

int bellerophon_gen_prov_msg2_data(uint8_t *ciphertext, uint32_t ciphertext_len, uint8_t *tag, uint32_t tag_len, uint8_t *iv, uint32_t iv_len, uint8_t *challenge) {
	sgx_enclave_id_t eid = 0;
        if (load_provision_enclave(&eid)) {
                printf("[provision_enclave.cpp] Failed to load provisioning enclave\n");
                return -1;
        }

	uint32_t retval;
	int ret = gen_prov_msg2_data_wrapper(eid, &retval, ciphertext, ciphertext_len, tag, tag_len, iv, iv_len, challenge);

	printf("PvE msg2 ret: %d, retval: %u\n", ret, retval);

	sgx_destroy_enclave(eid);

	return ret;
}
