#include "enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_enclave_init_t {
	int ms_retval;
} ms_ecall_enclave_init_t;

typedef struct ms_ecall_sign_t {
	int ms_retval;
} ms_ecall_sign_t;

typedef struct ms_ecall_shutdown_t {
	int ms_retval;
} ms_ecall_shutdown_t;

typedef struct ms_ocall_write_t {
	sgx_status_t ms_retval;
	uint8_t* ms_buf;
	int32_t ms_buflen;
} ms_ocall_write_t;

typedef struct ms_print_string_ocall_t {
	char* ms_str;
} ms_print_string_ocall_t;

static sgx_status_t SGX_CDECL enclave_ocall_write(void* pms)
{
	ms_ocall_write_t* ms = SGX_CAST(ms_ocall_write_t*, pms);
	ms->ms_retval = ocall_write((const uint8_t*)ms->ms_buf, ms->ms_buflen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_print_string_ocall(void* pms)
{
	ms_print_string_ocall_t* ms = SGX_CAST(ms_print_string_ocall_t*, pms);
	print_string_ocall((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[2];
} ocall_table_enclave = {
	2,
	{
		(void*)enclave_ocall_write,
		(void*)enclave_print_string_ocall,
	}
};
sgx_status_t ecall_enclave_init(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_enclave_init_t ms;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_sign(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_sign_t ms;
	status = sgx_ecall(eid, 1, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_shutdown(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_shutdown_t ms;
	status = sgx_ecall(eid, 2, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

