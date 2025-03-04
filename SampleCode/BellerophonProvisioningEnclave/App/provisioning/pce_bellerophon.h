#ifndef _PCE_BELLEROPHON_H
#include "sgx_pce.h"

sgx_pce_error_t get_pce_target(sgx_target_info_t *p_target, sgx_isv_svn_t *p_isvsvn);

sgx_pce_error_t get_pce_info(const sgx_report_t *p_report,
    const uint8_t *p_pek,
    uint32_t pek_size,
    uint8_t crypto_suite,
    uint8_t *p_encrypted_ppid,
    uint32_t encrypted_ppid_size,
    uint32_t *p_encrypted_ppid_out_size,
    sgx_isv_svn_t* p_pce_isvsvn,
    uint16_t* p_pce_id,
    uint8_t *p_signature_scheme);


#endif


