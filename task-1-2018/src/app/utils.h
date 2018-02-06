#pragma once
#ifndef _UTILS_H_
#define _UTILS_H_

#include <sgx_urts.h>
#include <sgx_tcrypto.h>

sgx_status_t create_enclave(const char* filename, sgx_enclave_id_t *eid);
sgx_status_t enclave_init(sgx_enclave_id_t eid);
sgx_status_t enclave_sign(sgx_enclave_id_t eid,
                          const char *data,
                          sgx_rsa3072_signature_t *signature);
sgx_status_t enclave_shutdown(sgx_enclave_id_t eid);

#endif
