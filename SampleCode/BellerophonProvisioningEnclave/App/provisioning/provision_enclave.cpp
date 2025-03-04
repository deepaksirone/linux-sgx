#include "sgx_urts.h"
#include "../../Enclave/Enclave.h"
#include "../Enclave_u.h"

#define PROVISION_ENCLAVE_FILENAME "enclave.signed.so"

static int load_provision_enclave(sgx_enclave_id_t *eid)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(PROVISION_ENCLAVE_FILENAME, 0, NULL, NULL, eid, NULL);
    if (ret != SGX_SUCCESS) {
        //print_error_message(ret);
        return -1;
    }

    return 0;
}

int bellerophon_gen_prov_msg1_data(const signed_pek_t* pek, const sgx_target_info_t* pce_target_info, sgx_report_t* msg1_output) {

	sgx_enclave_id_t eid = 0;
	if (load_provision_enclave(&eid)) {
		return -1;
	}
	
	uint32_t retval;
	int ret = bellerophon_gen_prov_msg1_data_wrapper(eid, &retval, pek, pce_target_info, msg1_output);

	sgx_destroy_enclave(eid);

	return ret;
}


