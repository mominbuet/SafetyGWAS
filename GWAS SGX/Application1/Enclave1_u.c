#include "Enclave1_u.h"
#include <errno.h>

typedef struct ms_foo_t {
	char* ms_buf_in;
	char* ms_buf;
	int ms_len;
} ms_foo_t;

typedef struct ms_hammingDistance_t {
	char** ms_input;
	int* ms_output;
	int ms_query;
	int ms_len_out;
	int ms_len_in;
	int ms_rowcount;
} ms_hammingDistance_t;

typedef struct ms_euclidieanDistance_t {
	char** ms_input;
	int* ms_output;
	int ms_query;
	int ms_len_out;
	int ms_len_in;
	int ms_rowcount;
} ms_euclidieanDistance_t;

typedef struct ms_ld_t {
	char** ms_input;
	char* ms_ldResult;
	int ms_len_ldmatrix;
	int ms_len_ldResult;
} ms_ld_t;

typedef struct ms_hwe_t {
	char** ms_input;
	char* ms_hweResult;
	int ms_len_hwematrix;
	int ms_len_hweResult;
} ms_hwe_t;

typedef struct ms_catt_t {
	char** ms_input;
	char* ms_cattResult;
	int ms_len_cattmatrix;
	int ms_len_cattResult;
} ms_catt_t;

typedef struct ms_fet_t {
	char** ms_input;
	char* ms_fetResult;
	int ms_len_fetmatrix;
	int ms_len_fetResult;
} ms_fet_t;

typedef struct ms_ocall_print_string_t {
	char* ms_str;
} ms_ocall_print_string_t;

static sgx_status_t SGX_CDECL Enclave1_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[1];
} ocall_table_Enclave1 = {
	1,
	{
		(void*)(uintptr_t)Enclave1_ocall_print_string,
	}
};

sgx_status_t foo(sgx_enclave_id_t eid, char* buf_in, char* buf, int len)
{
	sgx_status_t status;
	ms_foo_t ms;
	ms.ms_buf_in = buf_in;
	ms.ms_buf = buf;
	ms.ms_len = len;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave1, &ms);
	return status;
}

sgx_status_t hammingDistance(sgx_enclave_id_t eid, char** input, int* output, int query, int len_out, int len_in, int rowcount)
{
	sgx_status_t status;
	ms_hammingDistance_t ms;
	ms.ms_input = input;
	ms.ms_output = output;
	ms.ms_query = query;
	ms.ms_len_out = len_out;
	ms.ms_len_in = len_in;
	ms.ms_rowcount = rowcount;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave1, &ms);
	return status;
}

sgx_status_t euclidieanDistance(sgx_enclave_id_t eid, char** input, int* output, int query, int len_out, int len_in, int rowcount)
{
	sgx_status_t status;
	ms_euclidieanDistance_t ms;
	ms.ms_input = input;
	ms.ms_output = output;
	ms.ms_query = query;
	ms.ms_len_out = len_out;
	ms.ms_len_in = len_in;
	ms.ms_rowcount = rowcount;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave1, &ms);
	return status;
}

sgx_status_t ld(sgx_enclave_id_t eid, char** input, char* ldResult, int len_ldmatrix, int len_ldResult)
{
	sgx_status_t status;
	ms_ld_t ms;
	ms.ms_input = input;
	ms.ms_ldResult = ldResult;
	ms.ms_len_ldmatrix = len_ldmatrix;
	ms.ms_len_ldResult = len_ldResult;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave1, &ms);
	return status;
}

sgx_status_t hwe(sgx_enclave_id_t eid, char** input, char* hweResult, int len_hwematrix, int len_hweResult)
{
	sgx_status_t status;
	ms_hwe_t ms;
	ms.ms_input = input;
	ms.ms_hweResult = hweResult;
	ms.ms_len_hwematrix = len_hwematrix;
	ms.ms_len_hweResult = len_hweResult;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave1, &ms);
	return status;
}

sgx_status_t catt(sgx_enclave_id_t eid, char** input, char* cattResult, int len_cattmatrix, int len_cattResult)
{
	sgx_status_t status;
	ms_catt_t ms;
	ms.ms_input = input;
	ms.ms_cattResult = cattResult;
	ms.ms_len_cattmatrix = len_cattmatrix;
	ms.ms_len_cattResult = len_cattResult;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave1, &ms);
	return status;
}

sgx_status_t fet(sgx_enclave_id_t eid, char** input, char* fetResult, int len_fetmatrix, int len_fetResult)
{
	sgx_status_t status;
	ms_fet_t ms;
	ms.ms_input = input;
	ms.ms_fetResult = fetResult;
	ms.ms_len_fetmatrix = len_fetmatrix;
	ms.ms_len_fetResult = len_fetResult;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave1, &ms);
	return status;
}

