#include <stdio.h>
#include <limits.h>
#include "se_trace.h"
#include "se_memcpy.h"
#include "se_thread.h"
#include "sgx_urts.h"
#include "metadata.h"
#include "aeerror.h"
#include "sgx_pce.h"

#include "pce_u.h"

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

struct PCE_status {
    se_mutex_t m_pce_mutex;
    sgx_ql_request_policy_t m_pce_enclave_load_policy;
    sgx_enclave_id_t m_pce_eid;
    sgx_misc_attribute_t m_pce_attributes;
    metadata_t m_pce_metadata;
    char pce_path[MAX_PATH];

    PCE_status() :
        m_pce_enclave_load_policy(SGX_QL_DEFAULT),
        m_pce_eid(0)
    {
        se_mutex_init(&m_pce_mutex);
        memset(&m_pce_attributes, 0, sizeof(m_pce_attributes));
        memset(&m_pce_metadata, 0, sizeof(m_pce_metadata));
        memset(pce_path, 0, sizeof(pce_path));
    }
    ~PCE_status() {
        if (m_pce_eid != 0) sgx_destroy_enclave(m_pce_eid);
        se_mutex_destroy(&m_pce_mutex);
    }
};

static PCE_status g_pce_status;


#include <limits.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#define PATH_SEPARATOR '/'
extern "C" sgx_status_t sgx_get_metadata(const char* enclave_file, metadata_t *metadata);
#define PCE_ENCLAVE_NAME "libsgx_pce.signed.so.1"
#define PCE_ENCLAVE_NAME_LEGACY "libsgx_pce_bellerophon.signed.so"


static sgx_pce_error_t load_pce(sgx_enclave_id_t *p_pce_eid,
    sgx_misc_attribute_t *p_pce_attributes,
    metadata_t *p_metadata)
{
    sgx_status_t sgx_status = SGX_SUCCESS;
    sgx_pce_error_t ret = SGX_PCE_INTERFACE_UNAVAILABLE;
    int enclave_lost_retry_time = 1;
#if defined(_MSC_VER)
    TCHAR pce_enclave_path[MAX_PATH] = _T("");
#else
    char pce_enclave_path[MAX_PATH] = PCE_ENCLAVE_NAME_LEGACY;
#endif

    int rc = se_mutex_lock(&g_pce_status.m_pce_mutex);
    if (rc != 1)
    {
        SE_TRACE(SE_TRACE_ERROR, "Failed to lock mutex");
        return SGX_PCE_INTERFACE_UNAVAILABLE;
    }

    do {
        // Load the PCE
        if (g_pce_status.m_pce_eid == 0)
        {
            //if (!get_pce_path(pce_enclave_path, MAX_PATH))
            //    break;
            if (SGX_SUCCESS != sgx_get_metadata(pce_enclave_path, &g_pce_status.m_pce_metadata))
                break;

            do
            {
                sgx_launch_token_t launch_token = { 0 };
                int launch_token_updated;
                SE_TRACE(SE_TRACE_NOTICE, "Call sgx_create_enclave for PCE. %s\n", pce_enclave_path);
		printf("Call sgx_create_enclave for PCE. %s\n", pce_enclave_path);

                sgx_status = sgx_create_enclave(PCE_ENCLAVE_NAME_LEGACY,
                    1,
                    &launch_token,
                    &launch_token_updated,
                    p_pce_eid,
                    p_pce_attributes);
                if (SGX_SUCCESS != sgx_status)
                {
                    printf("Error, call sgx_create_enclave for PCE fail [%s], SGXError:%d .\n", __FUNCTION__, sgx_status);
                } else {
		    printf("Loaded PCE enclave\n");
		}

                // Retry in case there was a power transition that resulted is losing the enclave.
            } while (SGX_ERROR_ENCLAVE_LOST == sgx_status && enclave_lost_retry_time--);
            if (sgx_status != SGX_SUCCESS)
            {
                if (sgx_status == SGX_ERROR_OUT_OF_EPC)
                    ret = SGX_PCE_OUT_OF_EPC;
                else
                    ret = SGX_PCE_INTERFACE_UNAVAILABLE;
                break;
            }
            g_pce_status.m_pce_eid = *p_pce_eid;
            memcpy_s(&g_pce_status.m_pce_attributes, sizeof(sgx_misc_attribute_t), p_pce_attributes, sizeof(sgx_misc_attribute_t));
        }
        else {
            *p_pce_eid = g_pce_status.m_pce_eid;
            memcpy_s(p_pce_attributes, sizeof(sgx_misc_attribute_t), &g_pce_status.m_pce_attributes, sizeof(sgx_misc_attribute_t));
        }
        if (p_metadata)
                memcpy_s(p_metadata, sizeof(metadata_t), &g_pce_status.m_pce_metadata, sizeof(metadata_t));

        ret = SGX_PCE_SUCCESS;
    } while(0);

    rc = se_mutex_unlock(&g_pce_status.m_pce_mutex);
    if (rc != 1)
    {
        SE_TRACE(SE_TRACE_ERROR, "Failed to unlock mutex");
        return SGX_PCE_INTERFACE_UNAVAILABLE;
    }

    printf("load pce ret: %d\n", ret);
    return ret;
}

static void unload_pce(bool force = false)
{
    printf("Unloading PCE force: %d\n", force);
    int rc = se_mutex_lock(&g_pce_status.m_pce_mutex);
    if (rc != 1)
    {
        SE_TRACE(SE_TRACE_ERROR, "Failed to lock mutex");
        return;
    }

    // Unload the PCE enclave
    if (g_pce_status.m_pce_eid &&
        (force || g_pce_status.m_pce_enclave_load_policy != SGX_QL_PERSISTENT)
        )
    {
        SE_TRACE(SE_TRACE_NOTICE, "unload pce enclave 0X%llX\n", g_pce_status.m_pce_eid);
        sgx_destroy_enclave(g_pce_status.m_pce_eid);
        g_pce_status.m_pce_eid = 0;
    } else {
	printf("[Unload PCE] sgx_destroy_enclave not called, eid: %lu, g_pce_status.m_pce_enclave_load_policy: %d\n", g_pce_status.m_pce_eid, g_pce_status.m_pce_enclave_load_policy);
    }

    rc = se_mutex_unlock(&g_pce_status.m_pce_mutex);
    if (rc != 1)
    {
        SE_TRACE(SE_TRACE_ERROR, "Failed to unlock mutex");
        return;
    }
}

sgx_pce_error_t get_pce_info(const sgx_report_t *p_report,
    const uint8_t *p_pek,
    uint32_t pek_size,
    uint8_t crypto_suite,
    uint8_t *p_encrypted_ppid,
    uint32_t encrypted_ppid_size,
    uint32_t *p_encrypted_ppid_out_size,
    sgx_isv_svn_t* p_pce_isvsvn,
    uint16_t* p_pce_id,
    uint8_t *p_signature_scheme)
{
    sgx_pce_error_t pce_status = SGX_PCE_SUCCESS;
    sgx_enclave_id_t pce_eid = 0;
    sgx_status_t sgx_status = SGX_SUCCESS;
    sgx_misc_attribute_t pce_attributes;
    uint32_t ae_error;
    uint32_t enclave_lost_retry_time = 1;
    pce_info_t pce_info;

    if ((NULL == p_report) ||
        (NULL == p_pek) ||
        (NULL == p_encrypted_ppid) ||
        (NULL == p_encrypted_ppid_out_size) ||
        (NULL == p_pce_isvsvn) ||
        (NULL == p_pce_id) ||
        (NULL == p_signature_scheme))
    {
        return(SGX_PCE_INVALID_PARAMETER);
    }

    do {
        // Load the PCE enclave
        pce_status = load_pce(&pce_eid,
            &pce_attributes,
            NULL);
        if (SGX_PCE_SUCCESS != pce_status)
        {
	    printf("Failed to load enclave: %d\n", pce_status);
            return pce_status;
        }
	printf("Here1\n");
	fflush(stdout);
        int rc = se_mutex_lock(&g_pce_status.m_pce_mutex);
        if (rc != 1)
        {
            printf("Failed to lock mutex\n");
            return SGX_PCE_INTERFACE_UNAVAILABLE;
        }
        // Call get_pc_info ecall
        sgx_status = get_pc_info(pce_eid,
            &ae_error,
            p_report,
            p_pek,
            pek_size,
            crypto_suite,
            p_encrypted_ppid,
            encrypted_ppid_size,
            p_encrypted_ppid_out_size,
            &pce_info,
            p_signature_scheme);
        rc = se_mutex_unlock(&g_pce_status.m_pce_mutex);
        if (rc != 1)
        {
            printf("Failed to unlock mutex\n");
            return SGX_PCE_INTERFACE_UNAVAILABLE;
        }
        if (SGX_ERROR_ENCLAVE_LOST != sgx_status)
            break;
	printf("Unloading PCE\n");
        unload_pce(true);
    } while (SGX_ERROR_ENCLAVE_LOST == sgx_status && enclave_lost_retry_time--);

    printf("sgx_status: %d\n", sgx_status);

    if (SGX_SUCCESS != sgx_status)
    {
        printf("call to get_pc_info() failed. sgx_status = %04x.\n", sgx_status);
        // /todo:  May want to retry on SGX_PCE_ENCLAVE_LOST caused by power transition
        if (SGX_ERROR_OUT_OF_EPC == sgx_status)
            pce_status = SGX_PCE_OUT_OF_EPC;
        else
            pce_status = SGX_PCE_INTERFACE_UNAVAILABLE;
    }
    else {
        switch (ae_error)
        {
        case AE_SUCCESS:
            *p_pce_isvsvn = pce_info.pce_isvn;
            *p_pce_id = pce_info.pce_id;
            pce_status = SGX_PCE_SUCCESS;
	    printf("PCE AE_SUCCESS\n");
            break;
        case AE_INVALID_PARAMETER:
            pce_status = SGX_PCE_INVALID_PARAMETER;
	    printf("PCE AE_INVALID_PARAMETER\n");
            break;
        case PCE_INVALID_REPORT:
            pce_status = SGX_PCE_INVALID_REPORT;
	    printf("PCE PCE_INVALID_REPORT\n");
            break;
        case PCE_CRYPTO_ERROR:
            pce_status = SGX_PCE_CRYPTO_ERROR;
	    printf("PCE PCE_CRYPTO_ERROR\n");
            break;
        case PCE_INVALID_PRIVILEGE:
            pce_status = SGX_PCE_INVALID_PRIVILEGE;
	    printf("PCE PCE_INVALID_PRIVILEGE\n");
            break;
        case AE_OUT_OF_MEMORY_ERROR:
	    printf("PCE AE_OOM_ERROR\n");
            pce_status = SGX_PCE_OUT_OF_EPC;
            break;
        default:
	    printf("AE ERROR: %d\n", ae_error);
	    printf("PCE SGX_PCE_UNEXPECTED\n");
            pce_status = SGX_PCE_UNEXPECTED;
        }
    }
    unload_pce();
    printf("pce_status: %d\n", pce_status);

    return pce_status;
}


sgx_pce_error_t get_pce_target(sgx_target_info_t *p_target,
    sgx_isv_svn_t *p_isvsvn)
{
    sgx_misc_attribute_t pce_attributes;
    sgx_enclave_id_t pce_eid = 0;
    metadata_t metadata;
    if ((NULL == p_target) ||
        (NULL == p_isvsvn))
    {
        return(SGX_PCE_INVALID_PARAMETER);
    }

    // Load the PCE enclave
    sgx_pce_error_t pce_status = load_pce(&pce_eid,
        &pce_attributes,
        &metadata);
    if (SGX_PCE_SUCCESS != pce_status)
    {
        return pce_status;
    }
    unload_pce();

    memset(p_target, 0, sizeof(*p_target));
    memcpy_s(&p_target->attributes, sizeof(p_target->attributes),
        &pce_attributes.secs_attr, sizeof(pce_attributes.secs_attr));
    memcpy_s(&p_target->misc_select, sizeof(p_target->misc_select),
        &pce_attributes.misc_select, sizeof(pce_attributes.misc_select));
    memcpy_s(&p_target->mr_enclave, sizeof(p_target->mr_enclave),
        &metadata.enclave_css.body.enclave_hash, sizeof(metadata.enclave_css.body.enclave_hash));

    *p_isvsvn = metadata.enclave_css.body.isv_svn;

    return SGX_PCE_SUCCESS;
}
