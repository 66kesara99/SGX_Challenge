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

#define SIZE 100

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

    char data[SIZE];
    sgx_rsa3072_signature_t signature;
    
    // TODO
    // Create the enclave
    printf("Creating an enclave..\n");
    ret = create_enclave(ENCLAVE_PATH, &eid);

    
    check_errors(ret);
    printf("Create enclave Success!\n");

    // Allow to specify sealed data path

    printf("Loading the key..\n");
    ret = enclave_init(eid);
    check_errors(ret);
    printf("Key loaded!\n");

    // Take input data to be signed
    printf("Input data to create signature..\n");
    scanf("%s", data);
    
    // Call enclave to sign the data

    printf("Calling enclave to sign the data..\n");
    ret = enclave_sign(eid, data, &signature);
    check_errors(ret);
    printf("Sign Data Success!\n");
  
    
    // Print out the signature

    printf("The signature...\n");
    printf("%s\n", data);

    // Shutdown the enclave and store the sealed data

    printf("Destroying the enclave..\n");
    enclave_shutdown(eid);
    check_errors(ret);
    printf("Enclave Destroyed!\n");
    


    return 0;
}
