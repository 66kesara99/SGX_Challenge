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

#include "utils.h"


#define ENCLAVE_PATH "build/enclave/enclave.signed.so"

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


int main(int argc, char* argv[])
{
    sgx_status_t ret;
    sgx_enclave_id_t eid;
    // TODO
    // Create the enclave
    printf("Creating an enclave..\n");
    ret = create_enclave(ENCLAVE_PATH, &eid);

    if (ret == SGX_SUCCESS){
      printf("Create enclave success!\n");
    } else {
      print_error_message(ret);
    }

    // Allow to specify sealed data path
    // Take input data to be signed
    // Call enclave to sign the data
    // Print out the signature
    // Shutdown the enclave and store the sealed data



    return 0;
}
