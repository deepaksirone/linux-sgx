
#include "sgx_tcrypto.h"
#include "pcl_common.h"


pcl_table_t g_bellerophon_tbl __attribute__((section(PCLTBL_SECTION_NAME))) =
{
    .pcl_state           = PCL_PLAIN,
    .reserved1           = {},
    .pcl_guid            = {},
    .sealed_blob_size    = 0 ,
    .reserved2           = {},
    .sealed_blob         = {},
    .decryption_key_hash = {},
    .num_rvas            = 0 ,
    .reserved3           = {},
    .rvas_sizes_tags_ivs = {}
};

