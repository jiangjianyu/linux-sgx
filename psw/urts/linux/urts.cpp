//
// Created by Maxxie Jiang on 2/8/2019.
//

#include <dlfcn.h>
#include "sgx_urts.h"
#include "sim.h"
#include <sys/mman.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sgx_edger8r.h>
#include <errno.h>

sgx_enclave_id_t eid = 0;

void* lib_fd = 0;

void* enclave_base = 0;

extern int __ENCLAVE_HEAP__;

typedef sgx_status_t (*enclave_entry_t)(sgx_enclave_id_t, const int, const void*, void*);

typedef sgx_status_t (*enclave_init_t)(void* enclave_base, int size, int heap_size, int stack_size, void* ocall_entry);

enclave_entry_t enclave_entry_func = 0;

typedef struct {
    size_t nr_ocall;
    void * table[1];
} ocall_entry;

extern ocall_entry ocall_table_enclave;

sgx_status_t SGXAPI sgx_create_enclave(const char *file_name, const int debug, sgx_launch_token_t *launch_token,
        int *launch_token_updated, sgx_enclave_id_t *enclave_id, sgx_misc_attribute_t *misc_attr) {
    (void)debug;
    (void)launch_token;
    (void)launch_token_updated;
    (void)enclave_id;
    (void)misc_attr;
    
    int enclave_size = __ENCLAVE_HEAP__;
    int fd = open("/dev/zero", O_RDWR);
    enclave_base = mmap(0, enclave_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    close(fd);

    // open enclave lib
    lib_fd = dlopen(file_name, RTLD_NOW | RTLD_LOCAL);
    if (lib_fd == 0) {
        printf("errono %s\n", dlerror());
        return SGX_ERROR_UNEXPECTED;
    }

    // hook sgx_ecall
    enclave_entry_func = (enclave_entry_t)dlsym(lib_fd, "sgx_ecall");
    if (!enclave_entry_func){
        printf("cannot find entry sgx_ecall\n");
        return SGX_ERROR_UNEXPECTED;
    } 

    // setup memory

    enclave_init_t enclave_init = (enclave_init_t)dlsym(lib_fd, "setup_memory_ocall");
    if (enclave_init == NULL) {
        printf("cannot find entry setup_memory_ocall\n");
        return SGX_ERROR_UNEXPECTED;
    }
    enclave_init(enclave_base, enclave_size, int(enclave_size * .8), enclave_size - int(enclave_size * .8), (void*)sgx_ocall);

    return SGX_SUCCESS;
}

sgx_status_t SGXAPI sgx_destroy_enclave(const sgx_enclave_id_t enclave_id) {
    (void)enclave_id;
    dlclose(lib_fd);
    return SGX_SUCCESS;
}

sgx_status_t sgx_ecall(const sgx_enclave_id_t enclave_id, const int proc, const void *ocall_table, void *ms)
{
    return enclave_entry_func(enclave_id, proc, ocall_table, ms);
}

typedef sgx_status_t (*ocall_t)(void*);

sgx_status_t sgx_ocall(const unsigned int index,
                       void* ms) {
    ocall_t ocall = (ocall_t)ocall_table_enclave.table[index];
    return ocall(ms);
}