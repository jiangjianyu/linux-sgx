
#include "trts_internal.h"
#include "sgx_eid.h"
#include "internal/thread_data.h"

sgx_ocall_t sgx_ocall_entry;

char* lastest_ocall_table;

sgx_enclave_id_t latest_enclave_id;

thread_data_t thread;
sys_word_t base_addr = 0;
sys_word_t limit_addr = 0;
// TODO: fill-in the structure

__attribute__ ((visibility ("default")))
sgx_status_t sgx_ecall(const sgx_enclave_id_t enclave_id, const int proc, const void *ocall_table, void *ms) {
    ecall_t ecall = (ecall_t)g_ecall_table.ecall_table[proc].ecall_addr;
    lastest_ocall_table = (char*)ocall_table;
    latest_enclave_id = enclave_id;
    return ecall(ms);
}

sgx_status_t sgx_ocall(const unsigned int index,
                       void* ms) {
    return sgx_ocall_entry(index, ms);
}

extern "C" {

thread_data_t *get_thread_data(void) {
    thread.stack_base_addr    =   (sys_word_t) &base_addr;
    thread.stack_limit_addr   =   (sys_word_t) &limit_addr;
    return (thread_data_t*)(&thread);
}

// unsigned long __stack_chk_guard = 0xBAAAAAAD;
}

