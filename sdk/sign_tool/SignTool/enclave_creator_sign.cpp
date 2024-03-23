/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/**
* File: 
*     enclave_creator_sign.cpp
* Description: 
*     Measure the necessary information of the enclave
* to calculate the HASH value using SHA256 algorithm. 
*/

#include "enclave_creator.h"
#include "sgx_eid.h"
#include "enclave_creator_sign.h"
#include "se_trace.h"
#include "sgx_error.h"
#include "util_st.h"
#include "util.h"
#include "se_page_attr.h"
#include "sgx_enclave_common.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#define DATA_BLOCK_SIZE 64
#define EID             0x44444444

uint64_t enclave_image_address = 0;
uint64_t elrange_start_address = 0;
uint64_t elrange_size = 0;

void print_digest(EVP_MD_CTX *m_ctx, uint64_t src) {
    // EVP_MD_CTX *tmp_ctx = EVP_MD_CTX_create();
    // EVP_MD_CTX_copy(tmp_ctx, m_ctx);

    // uint8_t temp_hash[SGX_HASH_SIZE];
    // memset(temp_hash, 0, SGX_HASH_SIZE);
    // unsigned int hash_len;

    // EVP_DigestFinal_ex(tmp_ctx, temp_hash, &hash_len);

    UNUSED(src);
    // printf("%lx\n", src);

    // for(uint i = 0; i < hash_len; i++) printf("0x%02x,", temp_hash[i]);
    // printf("\n");

    // for (uint i = 0; i < sizeof(EVP_MD); i++) {
    //     printf("0x%02x,", reinterpret_cast<const uint8_t*>(m_ctx->digest)[i]);
    // }
    // printf("\n");
    // for (uint i = 0; i < sizeof(EVP_MD_CTX); i++) {
    //     printf("0x%02x,", reinterpret_cast<uint8_t*>(m_ctx)[i]);
    // }
    // printf("\n");
    for(int i = 0; i < 32; i++) printf("0x%02x,", reinterpret_cast<uint8_t*>(EVP_MD_CTX_get0_md_data(m_ctx))[i]);

    printf("\n");
    // printf(" %x %x %x\n", m_ctx->digest->md_size, m_ctx->digest->block_size, m_ctx->digest->ctx_size);

    // if(tmp_ctx)
    //     EVP_MD_CTX_destroy(tmp_ctx);
}


EnclaveCreatorST::EnclaveCreatorST()
{
    m_hash_valid_flag = false;
    memset(m_enclave_hash, 0, SGX_HASH_SIZE);
    m_ctx = NULL;
    m_eid = EID;
    m_quota = 0;
    memset(&m_mage, 0, sizeof(m_mage));
}

EnclaveCreatorST::~EnclaveCreatorST()
{
    if(m_ctx)
        EVP_MD_CTX_destroy(m_ctx);
}

int EnclaveCreatorST::create_enclave(secs_t *secs, sgx_enclave_id_t *enclave_id, void **start_addr, const uint32_t ex_features, const void* ex_features_p[32])
{
    printf("Create Enclave called\n");
    if(!secs || !enclave_id || !start_addr)
    {
        se_trace(SE_TRACE_DEBUG, "ERROR: Bad pointer.\n");
        return SGX_ERROR_UNEXPECTED;
    }

    if(ex_features == ENCLAVE_CREATE_EX_EL_RANGE && ex_features_p[ENCLAVE_CREATE_EX_EL_RANGE_BIT_IDX] != NULL)
    {
        enclave_elrange_t *enclave_elrange =  reinterpret_cast<enclave_elrange_t *>(const_cast<void *>(ex_features_p[ENCLAVE_CREATE_EX_EL_RANGE_BIT_IDX]));
        elrange_size = enclave_elrange->elrange_size;
        elrange_start_address = enclave_elrange->elrange_start_address;
        enclave_image_address = enclave_elrange->enclave_image_address;
    }
    
    memset(m_enclave_hash, 0, SGX_HASH_SIZE);
    if((m_ctx = EVP_MD_CTX_create()) == NULL)
    {
        se_trace(SE_TRACE_DEBUG, "ERROR - EVP_MD_CTX_create: %s.\n", ERR_error_string(ERR_get_error(), NULL));
        return SGX_ERROR_UNEXPECTED;
    }
    if(EVP_DigestInit_ex(m_ctx, EVP_sha256(), NULL) != 1)
    {
        se_trace(SE_TRACE_DEBUG, "ERROR - EVP_DigestInit_ex: %s.\n", ERR_error_string(ERR_get_error(), NULL));
        return SGX_ERROR_UNEXPECTED;
    }
    m_mage.size += DATA_BLOCK_SIZE;

    uint8_t ecreat_val[SIZE_NAMED_VALUE] = "ECREATE";
    
    uint64_t size= secs->size;
    if(elrange_size != 0)
    {
        size = elrange_size;
    }
    uint8_t data_block[DATA_BLOCK_SIZE];
    size_t offset = 0;
    memset(data_block, 0, DATA_BLOCK_SIZE);
    memcpy_s(data_block, sizeof(data_block), ecreat_val, SIZE_NAMED_VALUE);
    offset += SIZE_NAMED_VALUE;
    memcpy_s(&data_block[offset], sizeof(data_block)-offset, &secs->ssa_frame_size, sizeof(secs->ssa_frame_size));
    offset += sizeof(secs->ssa_frame_size);
    memcpy_s(&data_block[offset], sizeof(data_block)-offset, &size, sizeof(uint64_t));

    if(EVP_DigestUpdate(m_ctx, &data_block, DATA_BLOCK_SIZE) != 1)
    {
        se_trace(SE_TRACE_DEBUG, "ERROR - EVP_DigestUpdate: %s.\n", ERR_error_string(ERR_get_error(), NULL));
        return SGX_ERROR_UNEXPECTED;
    }

    *enclave_id = m_eid;
    *start_addr = secs->base;
    return SGX_SUCCESS;
}

int EnclaveCreatorST::add_enclave_page(sgx_enclave_id_t enclave_id, void *src, uint64_t offset, const sec_info_t &sinfo, uint32_t attr)
{   
    assert(m_ctx!=NULL);
    UNUSED(enclave_id);
    void* source = src;
    uint8_t color_page[SE_PAGE_SIZE];
    if(!source)
    {
        memset(color_page, 0, SE_PAGE_SIZE);
        source = reinterpret_cast<void*>(&color_page);
    }

    for(unsigned int i = 0; i< sizeof(sinfo.reserved)/sizeof(sinfo.reserved[0]); i++)
    {
        if(sinfo.reserved[i] != 0)
            return SGX_ERROR_UNEXPECTED;
    }
    /* sinfo.flags[64:16] should be 0 */
    if((sinfo.flags & (~SI_FLAGS_EXTERNAL)) != 0)
    {
        return SGX_ERROR_UNEXPECTED;
    }

    //check the page attributes
    if (!(attr & PAGE_ATTR_EADD))
    {
        return SGX_SUCCESS;
    }

    uint64_t page_offset = (uint64_t)offset;
    if(elrange_size != 0)
    {
        page_offset += enclave_image_address - elrange_start_address;
    }
    
    uint8_t eadd_val[SIZE_NAMED_VALUE] = "EADD\0\0\0";

    uint8_t data_block[DATA_BLOCK_SIZE];
    size_t db_offset = 0;
    memset(data_block, 0, DATA_BLOCK_SIZE);
    memcpy_s(data_block, sizeof(data_block), eadd_val, SIZE_NAMED_VALUE);
    db_offset += SIZE_NAMED_VALUE;
    memcpy_s(data_block+db_offset, sizeof(data_block)-db_offset, &page_offset, sizeof(page_offset));
    db_offset += sizeof(page_offset);
    memcpy_s(data_block+db_offset, sizeof(data_block)-db_offset, &sinfo, sizeof(data_block)-db_offset);
    if(EVP_DigestUpdate(m_ctx, data_block, DATA_BLOCK_SIZE) != 1)
    {
        se_trace(SE_TRACE_DEBUG, "ERROR - EVP_digestUpdate: %s.\n", ERR_error_string(ERR_get_error(), NULL));
        return SGX_ERROR_UNEXPECTED;
    }

    m_mage.size += DATA_BLOCK_SIZE;

    /* If the page need to eextend, do eextend. */
    if((attr & ADD_EXTEND_PAGE) == ADD_EXTEND_PAGE)
    {
        uint8_t *pdata = (uint8_t *)source;
        uint8_t eextend_val[SIZE_NAMED_VALUE] = "EEXTEND";

#define EEXTEND_TIME  4 
        for(int i = 0; i < SE_PAGE_SIZE; i += (DATA_BLOCK_SIZE * EEXTEND_TIME))
        {
            db_offset = 0;
            memset(data_block, 0, DATA_BLOCK_SIZE);
            memcpy_s(data_block, sizeof(data_block), eextend_val, SIZE_NAMED_VALUE);
            db_offset += SIZE_NAMED_VALUE;
            memcpy_s(data_block+db_offset, sizeof(data_block)-db_offset, &page_offset, sizeof(page_offset));
            if(EVP_DigestUpdate(m_ctx, data_block, DATA_BLOCK_SIZE) != 1)
            {
                se_trace(SE_TRACE_DEBUG, "ERROR - EVP_digestUpdate: %s.\n", ERR_error_string(ERR_get_error(), NULL));
                return SGX_ERROR_UNEXPECTED;
            }

	    m_mage.size += DATA_BLOCK_SIZE;

            for(int j = 0; j < EEXTEND_TIME; j++)
            {
                memcpy_s(data_block, sizeof(data_block), pdata, DATA_BLOCK_SIZE);
                if(EVP_DigestUpdate(m_ctx, data_block, DATA_BLOCK_SIZE) != 1)
                {
                    se_trace(SE_TRACE_DEBUG, "ERROR - EVP_digestUpdate: %s.\n", ERR_error_string(ERR_get_error(), NULL));
                    return SGX_ERROR_UNEXPECTED;
                }
		m_mage.size += DATA_BLOCK_SIZE;
                pdata += DATA_BLOCK_SIZE;
                page_offset += DATA_BLOCK_SIZE;
            }
        }
    }

    m_quota += SE_PAGE_SIZE;
    return SGX_SUCCESS;
}

int EnclaveCreatorST::init_enclave(sgx_enclave_id_t enclave_id, enclave_css_t *enclave_css, SGXLaunchToken *lc, le_prd_css_file_t *prd_css_file)
{
    assert(m_ctx != NULL);
    UNUSED(enclave_id), UNUSED(enclave_css), UNUSED(lc), UNUSED(prd_css_file);

    printf("BEFORE EINIT\n");
    //printf("Testing Message\n");
    //assert(m_ctx->md_data == NULL);
    //printf("Assertion passed\n");
    if (EVP_MD_CTX_get0_md_data(m_ctx) != NULL) {
    	memcpy_s(m_mage.digest, SGX_HASH_SIZE, reinterpret_cast<uint8_t*>(EVP_MD_CTX_get0_md_data(m_ctx)), SGX_HASH_SIZE);
    	printf("AFTER MEMCPY\n");
    } else {
    	SHA256_CTX *sha_ctx = (SHA256_CTX *)m_ctx->algctx;
	memcpy_s(&m_mage.sha256_state, sizeof(SHA256_CTX), reinterpret_cast<uint8_t*>(m_ctx->algctx), sizeof(SHA256_CTX));
    	printf("Printing ALGCTX Hash in little endian: ");
    	for (uint64_t i = 0; i < SGX_HASH_SIZE; i++) printf("0x%02x,", reinterpret_cast<uint8_t*>(sha_ctx->h)[i]);
	printf("\n");
    }

    // uint8_t cnts[16];
    // memset(cnts, 0, 16);
    // memcpy_s(cnts, 16, reinterpret_cast<uint8_t*>(&m_maise.size), sizeof(m_maise.size));
    //for (uint64_t i = 0; i < sizeof(m_mage); i++) printf("0x%02x,", reinterpret_cast<uint8_t*>(&m_mage)[i]);
    // print_digest(m_ctx, 0);

    uint8_t temp_hash[SGX_HASH_SIZE];
    memset(temp_hash, 0, SGX_HASH_SIZE);
    unsigned int hash_len;

    /* Complete computation of the SHA256 digest and store the result into the hash. */
    if(EVP_DigestFinal_ex(m_ctx, temp_hash, &hash_len) != 1)
    {
        se_trace(SE_TRACE_DEBUG, "ERROR - EVP_digestFinal_ex: %s.\n", ERR_error_string(ERR_get_error(), NULL));
        return SGX_ERROR_UNEXPECTED;
    }

    printf("FINAL DIGEST\n");
    for(uint i = 0; i < hash_len; i++) printf("0x%02x,", temp_hash[i]);
    printf("\n");
    for (int i = 0; i< SGX_HASH_SIZE; i++)
    {
        m_enclave_hash[i] = temp_hash[i];
    }
    m_hash_valid_flag = true;
    return SGX_SUCCESS;
}

int EnclaveCreatorST::get_misc_attr(sgx_misc_attribute_t *sgx_misc_attr, metadata_t *metadata, SGXLaunchToken * const lc, uint32_t flag)
{
    UNUSED(metadata), UNUSED(lc), UNUSED(flag);
    memset(sgx_misc_attr, 0, sizeof(sgx_misc_attribute_t));
    return SGX_SUCCESS;
}

int EnclaveCreatorST::destroy_enclave(sgx_enclave_id_t enclave_id, uint64_t enclave_size)
{
    UNUSED(enclave_id);
    UNUSED(enclave_size);
    if(m_ctx){
        EVP_MD_CTX_destroy(m_ctx);
        m_ctx = NULL;
    }
    return SGX_SUCCESS;
}

bool EnclaveCreatorST::get_plat_cap(sgx_misc_attribute_t *se_attr)
{
    UNUSED(se_attr);
    return false;
}

int EnclaveCreatorST::initialize(sgx_enclave_id_t enclave_id)
{
    UNUSED(enclave_id);
    return SGX_SUCCESS;
}

bool EnclaveCreatorST::use_se_hw() const
{
    return false;
}

bool EnclaveCreatorST::is_EDMM_supported(sgx_enclave_id_t enclave_id)
{
    UNUSED(enclave_id);
    return false;
}

bool EnclaveCreatorST::is_driver_compatible()
{
    return true;
}


int EnclaveCreatorST::get_enclave_info(uint8_t *hash, int size, uint64_t *quota, sgx_mage_entry_t *mage_t)
{
    if(hash == NULL || size != SGX_HASH_SIZE || m_hash_valid_flag == false)
    {
        se_trace(SE_TRACE_DEBUG, "ERROR: something went wrong in the function get_enclave_hash().\n");
        return SGX_ERROR_UNEXPECTED;
    }
    else
    {
        memcpy_s(hash, size, m_enclave_hash, SGX_HASH_SIZE);
    }
    *quota = m_quota;
    if (mage_t == NULL) {
        se_trace(SE_TRACE_DEBUG, "ERROR: something went wrong in the function get_enclave_hash().\n");
    } else {
        memcpy_s(mage_t, sizeof(m_mage), &m_mage, sizeof(m_mage));
    }
    return SGX_SUCCESS;
}

static EnclaveCreatorST g_enclave_creator_st;
EnclaveCreator* g_enclave_creator = &g_enclave_creator_st;
