
#include "sgx_trts.h"
#include "trts_util.h"
#include "trts_internal.h"
#include "sgx_trts_exception.h"
#include "internal/thread_data.h"

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
    heap_base = (char*)enclave_base + sizeof(thread_data_t);
    heap_size -= (int)sizeof(thread_data_t);
    stack_base = (char*)enclave_base + heap_size;
    sgx_ocall_entry = (sgx_ocall_t)ocall_entry;

    thread_data_t *this_thread = (thread_data_t*)enclave_base;
    this_thread->self_addr = (sys_word_t)enclave_base;
    this_thread->stack_base_addr = (sys_word_t)stack_base;
    this_thread->stack_limit_addr = (sys_word_t)((char*)stack_base + stack_size);

    enclave_size = size;
    return SGX_SUCCESS;
}

void* get_enclave_base() {
    return enclave_base;
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

sgx_status_t SGXAPI sgx_read_rand(unsigned char *rand, size_t length_in_bytes) {
    (void) rand;
    (void) length_in_bytes;   
    return SGX_SUCCESS;
}

int SGXAPI sgx_is_outside_enclave(const void *addr, size_t size) {
    return !sgx_is_within_enclave(addr, size);
}

dl_entry get_function;
dl_entry get_addr_name;

__attribute__ ((visibility ("default")))
sgx_status_t setup_dl_entry(void *get_func_addr, void *get_addr_name_addr) {
    get_function    = (dl_entry) get_func_addr;
    get_addr_name   = (dl_entry) get_addr_name_addr;
    return SGX_SUCCESS;
}


void* SGXAPI sgx_get_func(const char *addr) {
    return (*get_function)(addr);
}

void* SGXAPI sgx_get_addr_name(const char *addr) {
    return (*get_addr_name)(addr);
}