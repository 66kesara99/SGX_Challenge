#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <pwd.h>

#include "sgx_uae_service.h"

#include "enclave_u.h"

#define TOKEN_FILENAME "enclave.token"
#define MAX_PATH FILENAME_MAX

// Utilities
int hex2bytes(const char* hex, int len, char* res) {
    for(int i = 0; i < len/2; i++) {
        sscanf(&(hex[i*2]), "%2hhx", &(res[i]));
    }

    // Each 2 hex characters is one byte
    return len/2;
}

// Prints an array of bytes in hexademical format
void print_byte_array(
    FILE *file, const void *mem, uint32_t len)
{
    if(!mem || !len)
    {
        fprintf(file, "\n( null )\n");
        return;
    }
    uint8_t *array = (uint8_t *)mem;
    fprintf(file, "%u bytes:\n{\n", len);
    uint32_t i = 0;
    for(i = 0; i < len - 1; i++)
    {
        fprintf(file, "0x%x, ", array[i]);
        if(i % 8 == 7) fprintf(file, "\n");
    }
    fprintf(file, "0x%x ", array[i]);
    fprintf(file, "\n}\n");
}


/*
 * Create the enclave instance
 * Call sgx_create_enclave to initialize an enclave instance
 */
sgx_status_t create_enclave(const char* enclave_filename, sgx_enclave_id_t *eid)
{
    int launch_token_update = 0;
    sgx_launch_token_t launch_token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Debug Support: set 2nd parameter to 1 */
    return sgx_create_enclave(enclave_filename, SGX_DEBUG_FLAG, &launch_token, &launch_token_update, eid, NULL);
}

// TODO
// Add the necessary parameters to call ecall_enclave_init
sgx_status_t enclave_init(sgx_enclave_id_t eid)
{
    int status = SGX_SUCCESS;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = ecall_enclave_init(eid, &status);

    if (ret != SGX_SUCCESS) {
        return ret;
    }
    if (status != SGX_SUCCESS) {
        return (sgx_status_t)status;
    }

    return SGX_SUCCESS;
}

// TODO
// Make a call to ecall_sign
// Change the parameters, if necessary (add data_len, or assume it is NULL-terminated)
sgx_status_t enclave_sign(sgx_enclave_id_t eid,
                          const char *data,
                          sgx_rsa3072_signature_t *signature)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int status = SGX_SUCCESS;
    
    ret = ecall_sign(eid, &status);
    if (ret != SGX_SUCCESS) {
        return ret;
    }
    
    return SGX_SUCCESS;
}

// TODO
// Call ecall_shutdown
sgx_status_t enclave_shutdown(sgx_enclave_id_t eid)
{

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int status = SGX_SUCCESS;
        
    ret = ecall_shutdown(eid, &status);
    if (ret != SGX_SUCCESS) {
        return ret;
    }
    
    ret = sgx_destroy_enclave(eid);

    return ret;
    
}
