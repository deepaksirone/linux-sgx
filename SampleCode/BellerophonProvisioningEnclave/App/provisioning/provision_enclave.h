#ifndef _PROVISION_ENCLAVE_H_
#define _PROVISION_ENCLAVE_H_

int bellerophon_gen_prov_msg1_data(const signed_pek_t* pek, const sgx_target_info_t* pce_target_info, sgx_report_t* msg1_output);

#endif
