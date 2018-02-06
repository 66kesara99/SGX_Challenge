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
    // TODO
    // Create the enclave
    //
    // Allow to specify the location of the enclave from the task-1
    // Or to specify the location of sealed data
    //
    // Perform Local Attestation with the enclave from task-1
    //
    // Use lib_la from libs or do Local Attestation based on SDK SampleCode
    //   - with lib_la the workflow is as follows:
    //   - implement la_verify_peer_enclave, la_restart, la_response_generator
    //   - call la_create and obtain the session id, use it in calls to la_* functions
    //   - call la_exchange with marshaled buffers (see below)
    //   - call la_close
    //
    // Obtain the key from the enclave from task-1
    //   - implement marshaling of the key to the buffer
    //   - implement unmarshaling of the key
    //   - if using lib_la call 
    //
    // Seal it
    //
    // If the location of sealed data is given act as the enclave from task-1
    //
    // Note: in the end the two enclaves will be identical
    return 0;
}
