#ifndef _PROVISION_ENCLAVE_H_
#define _PROVISION_ENCLAVE_H_

int bellerophon_gen_prov_msg1_data(const signed_pek_t* pek, const sgx_target_info_t* pce_target_info, sgx_report_t* msg1_output);
int bellerophon_gen_prov_msg2_data(uint8_t *ciphertext, uint32_t ciphertext_len, uint8_t *tag, uint32_t tag_len, uint8_t *iv, uint32_t iv_len, uint8_t *challenge);
#endif
