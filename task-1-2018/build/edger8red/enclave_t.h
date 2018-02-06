#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_tcrypto.h"
#include "sgx_tseal.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


int ecall_enclave_init();
int ecall_sign();
int ecall_shutdown();

sgx_status_t SGX_CDECL ocall_write(sgx_status_t* retval, const uint8_t* buf, int32_t buflen);
sgx_status_t SGX_CDECL print_string_ocall(const char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
