#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <poll.h>

#include <sgx_urts.h>
#include <sgx_uae_service.h>

#include "enclave_u.h"

#include "sample_libcrypto.h"

#include "sgx_errors.h"

#define ENCLAVE_PATH "build/enclave/enclave.signed.so"

// Defines

#include "utils.h"
#include <stdlib.h>

/* OCall functions */
sgx_status_t ocall_write(const uint8_t *buf, int32_t buflen)
{
    for( int i = 0; i < buflen; i++ ){
        printf("%#01x ", buf[i]);
    }

    return SGX_SUCCESS;
}

void print_string_ocall(const char *str)
{
    printf("%s", str);
}


void check_errors(sgx_status_t ret){
  int status;
  if (ret != SGX_SUCCESS){
    print_error_message(ret);
    exit(status);
  }
}


int main(int argc, char* argv[])
{
    sgx_status_t ret;
    sgx_enclave_id_t eid;

    char* data;
    sgx_rsa3072_signature_t signature;
    
    // TODO
    // Create the enclave
    printf("Creating an enclave..\n");
    ret = create_enclave(ENCLAVE_PATH, &eid);

    
    check_errors(ret);
    printf("Create enclave Success!\n");

    // Allow to specify sealed data path

    enclave_init(eid);
    // Take input data to be signed
    // Call enclave to sign the data

    ret = enclave_sign(eid, data, &signature);
    check_errors(ret);
    printf("Sign Data Success!\n");
  
    
    // Print out the signature
    // Shutdown the enclave and store the sealed data

    printf("Destroying an enclave..\n");

    enclave_shutdown(eid);

    check_errors(ret);
    printf("Enclave Destroyed!\n");
    


    return 0;
}
