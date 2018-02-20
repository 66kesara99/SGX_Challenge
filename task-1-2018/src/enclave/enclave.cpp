#include <stdarg.h>
#include <stdio.h>
#include <cstring>
#include <cassert>
#include <map>
#include <vector>

#include "sgx_tcrypto.h"
#include "sgx_tseal.h"
#include "sgx_trts.h"
#include "sgx_utils.h"
#include "sgx_report.h"
#include "sgx_thread.h"
#include "sgx_tae_service.h"
#include "sgx_spinlock.h"

#include "enclave_t.h"

static sgx_cmac_128bit_key_t g_key = {0x0};
static bool initialized = false;

#define SGX_MISCSEL_EXINFO     0x00000001  /* report #PF and #GP inside enclave */
#define TSEAL_DEFAULT_MISCMASK (~SGX_MISCSEL_EXINFO)

#define BUF_SIZE 100
char buf[BUF_SIZE];  // Buffer for printfs

// Enclave API
// TODO
// Unseals the key or generates a new key
// If size_sdata is 0, generates a new key
int ecall_enclave_init()
{
    initialized = true;

    strncpy(buf, "Loading key from the memory..\n", BUF_SIZE);
    print_string_ocall(buf);
    strncpy(buf, "Generating a new key..\n", BUF_SIZE);
    print_string_ocall(buf);
    return SGX_SUCCESS;
}

// TODO
// Sign data with the key
int ecall_sign()
{
    if( !initialized ) {
        return SGX_ERROR_UNEXPECTED;
    }

    strncpy(buf, "Signing the key..\n", BUF_SIZE);
    print_string_ocall(buf);
    return SGX_SUCCESS;
}

// TODO
// Seal the key
int ecall_shutdown()
{
    initialized = false;

    strncpy(buf, "Saving key to the storage..\n", BUF_SIZE);
    print_string_ocall(buf);
    strncpy(buf, "enclave is shutting down..\n", BUF_SIZE);
    print_string_ocall(buf);
    return SGX_SUCCESS;
}
