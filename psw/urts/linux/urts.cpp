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
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <malloc.h>
#include "tee_client_api.h"
#include "err.h"

TEEC_Context ctx;
TEEC_Session sess;
extern TEEC_UUID uuid;

sgx_enclave_id_t eid = 0;

void *lib_fd = 0;

void *enclave_base = 0;

extern int __ENCLAVE_HEAP__;

typedef sgx_status_t (*enclave_entry_t)(sgx_enclave_id_t, const int, const void *, void *);

typedef sgx_status_t (*enclave_init_t)(void *enclave_base, int size, int heap_size, int stack_size, void *ocall_entry);

enclave_entry_t enclave_entry_func = 0;

typedef struct
{
	size_t nr_ocall;
	void *table[1];
} ocall_entry;

extern ocall_entry ocall_table_enclave;

sgx_enclave_id_t global_eid = 0;

typedef sgx_status_t (*ocall_func_entry)(void *pms);

extern "C" sgx_status_t init_sgx_buffer();

sgx_status_t sgx_create_enclave(const char *file_name, const int debug, sgx_launch_token_t *launch_token, int *launch_token_updated, sgx_enclave_id_t *enclave_id, sgx_misc_attribute_t *misc_attr)
{

	(void)(file_name);
	(void)(debug);
	(void)(launch_token);
	(void)(launch_token_updated);
	(void)(misc_attr);

	uint32_t err_origin;

	TEEC_Operation operation;

	/*MUST use TEEC_LOGIN_IDENTIFY method*/
	memset(&operation, 0x00, sizeof(operation));
	operation.started = 1;
	operation.paramTypes = TEEC_PARAM_TYPES(
		TEEC_NONE,
		TEEC_NONE,
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_INPUT);

	TEEC_Result res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/*
	 * Open a session to the "hello world" TA, the TA will print "hello
	 * world!" in the log when the session is created.
	 */
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
						   TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			 res, err_origin);

	*enclave_id = ++global_eid;

	if (init_sgx_buffer() != SGX_SUCCESS) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	return res;
}

sgx_status_t SGXAPI sgx_destroy_enclave(const sgx_enclave_id_t enclave_id)
{
	(void)(enclave_id);
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	return SGX_SUCCESS;
}

typedef sgx_status_t (*ocall_t)(void *);

typedef struct thread_data_t
{
	char *buffer;
	void **ocall_table;
} thread_data;

void *thread_func(void *arg)
{
	thread_data *td = (thread_data *)arg;
	char *buffer = td->buffer;
	volatile char *status = buffer;
	int *ocall_idx_ptr = (int *)(buffer + sizeof(char));
	void **ocall_table = (void **)td->ocall_table;
	printf("ocall thread entered\n");
	while (*status != 111)
	{
		if (*status == 1)
		{
			// if there are
			printf("ocall %d\n", *ocall_idx_ptr);
			ocall_func_entry entry = (ocall_func_entry)ocall_table[*ocall_idx_ptr];
			sgx_status_t r = (*entry)(buffer + sizeof(char) + sizeof(int));
			*status = (char)r;
		}
	}
	printf("ocall thread exited\n");
	return NULL;
}

sgx_status_t ocall_add(char *ocall_buffer, void **ocall_table)
{
	thread_data *td = (thread_data *)malloc(sizeof(thread_data));
	td->buffer = ocall_buffer;
	td->ocall_table = ocall_table;
	pthread_t thd_idx;
	// Create a thread that will function threadFunc()
	int err = pthread_create(&thd_idx, NULL, &thread_func, td);
	if (err)
	{
		printf("error in creating ocall thread\n");
		return SGX_SUCCESS + 1;
	}
	return SGX_SUCCESS;
}

sgx_status_t ocall_del(char *ocall_buffer)
{
	volatile char *status = ocall_buffer;
	// stop the ocall thread
	*status = 111;
	return SGX_SUCCESS;
}
