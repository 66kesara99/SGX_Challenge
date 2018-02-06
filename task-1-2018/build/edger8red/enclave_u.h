#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */

#include "sgx_tcrypto.h"
#include "sgx_tseal.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_write, (const uint8_t* buf, int32_t buflen));
void SGX_UBRIDGE(SGX_NOCONVENTION, print_string_ocall, (const char* str));

sgx_status_t ecall_enclave_init(sgx_enclave_id_t eid, int* retval);
sgx_status_t ecall_sign(sgx_enclave_id_t eid, int* retval);
sgx_status_t ecall_shutdown(sgx_enclave_id_t eid, int* retval);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
