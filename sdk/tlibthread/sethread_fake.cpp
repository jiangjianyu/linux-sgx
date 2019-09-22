

#include "sethread_internal.h"

extern "C" sgx_status_t sgx_thread_wait_untrusted_event_ocall(int* retval, const void *self) {
    (void)(retval);
    (void)(self);
    return SGX_SUCCESS;
}
extern "C" sgx_status_t sgx_thread_set_untrusted_event_ocall(int* retval, const void *waiter) {
    (void)(retval);
    (void)(waiter);
    return SGX_SUCCESS;
}
extern "C" sgx_status_t sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total) {
    (void)(retval);
    (void)(waiters);
    (void)(total);
    return SGX_SUCCESS;
}
extern "C" sgx_status_t sgx_thread_setwait_untrusted_events_ocall(int* retval, const void *waiter, const void *self) {
    (void)(retval);
    (void)(waiter);
    (void)(self);
    return SGX_SUCCESS;
}
