#include "enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


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

static sgx_status_t SGX_CDECL sgx_ecall_enclave_init(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_enclave_init_t));
	ms_ecall_enclave_init_t* ms = SGX_CAST(ms_ecall_enclave_init_t*, pms);
	sgx_status_t status = SGX_SUCCESS;


	ms->ms_retval = ecall_enclave_init();


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_sign(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_sign_t));
	ms_ecall_sign_t* ms = SGX_CAST(ms_ecall_sign_t*, pms);
	sgx_status_t status = SGX_SUCCESS;


	ms->ms_retval = ecall_sign();


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_shutdown(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_shutdown_t));
	ms_ecall_shutdown_t* ms = SGX_CAST(ms_ecall_shutdown_t*, pms);
	sgx_status_t status = SGX_SUCCESS;


	ms->ms_retval = ecall_shutdown();


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[3];
} g_ecall_table = {
	3,
	{
		{(void*)(uintptr_t)sgx_ecall_enclave_init, 0},
		{(void*)(uintptr_t)sgx_ecall_sign, 0},
		{(void*)(uintptr_t)sgx_ecall_shutdown, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[2][3];
} g_dyn_entry_table = {
	2,
	{
		{0, 0, 0, },
		{0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_write(sgx_status_t* retval, const uint8_t* buf, int32_t buflen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = buflen;

	ms_ocall_write_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_write_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_write_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_write_t));

	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memcpy((void*)ms->ms_buf, buf, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_buflen = buflen;
	status = sgx_ocall(0, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL print_string_ocall(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_print_string_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_print_string_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_print_string_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_print_string_ocall_t));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_str);
		memcpy((void*)ms->ms_str, str, _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(1, ms);


	sgx_ocfree();
	return status;
}

