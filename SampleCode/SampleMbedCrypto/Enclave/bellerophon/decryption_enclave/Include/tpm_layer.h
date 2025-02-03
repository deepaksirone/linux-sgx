#ifndef _TPM_LAYER_H_
#define _TPM_LAYER_H_

extern "C" int attest_tpm(unsigned char *pem_certificate);
extern "C" int store_hibe_key(unsigned char *hibe_key, int hibe_key_size, int nv_index, unsigned char *password, int passwd_size);
extern "C" int load_hibe_key(unsigned char *hibe_key, int *hibe_key_size, unsigned char *password, unsigned long int passwd_size);

#endif
