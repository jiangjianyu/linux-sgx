
#include "sgx_trts.h"
#include "trts_util.h"
#include "trts_internal.h"
#include "sgx_trts_exception.h"

void* enclave_base = NULL;
void* heap_base = NULL;
void* stack_base = NULL;
int enclave_size = 0;

extern sgx_ocall_t sgx_ocall_entry;

// No need to check the state of enclave or thread.
// The functions should be called within an ECALL, so the enclave and thread must be initialized at that time.
void * get_heap_base(void)
{
    return heap_base;
}

size_t get_heap_size(void)
{
    return (size_t)((intptr_t)stack_base - (intptr_t)enclave_base);
}

__attribute__ ((visibility ("default")))
sgx_status_t setup_memory_ocall(void *eb, int size, int heap_size, int stack_size, void *ocall_entry) {
    if (eb == NULL) {
        return SGX_ERROR_MEMORY_MAP_CONFLICT;
    }
    if (stack_size + heap_size != size) {
        return SGX_ERROR_MEMORY_MAP_CONFLICT;
    }
    enclave_base = eb;
    heap_base = enclave_base;
    stack_base = (char*)enclave_base + heap_size;
    sgx_ocall_entry = (sgx_ocall_t)ocall_entry;
    enclave_size = size;
    return SGX_SUCCESS;
}

int error_internal;

int * get_errno_addr(void) {
    return &error_internal;
}

int sgx_is_within_enclave(const void *addr, size_t size) {
    return ((char*)addr >= (char*)enclave_base 
        && (char*)addr + size < (char*)enclave_base + enclave_size);
}

void * SGXAPI sgx_register_exception_handler(int is_first_handler, sgx_exception_handler_t exception_handler) {
    (void) is_first_handler;
    (void) exception_handler;
    return NULL;
}