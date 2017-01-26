#include "Enclave1_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


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

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#pragma warning(disable: 4200)
#endif

static sgx_status_t SGX_CDECL sgx_foo(void* pms)
{
	ms_foo_t* ms = SGX_CAST(ms_foo_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_buf_in = ms->ms_buf_in;
	int _tmp_len = ms->ms_len;
	size_t _len_buf_in = _tmp_len;
	char* _in_buf_in = NULL;
	char* _tmp_buf = ms->ms_buf;
	size_t _len_buf = _tmp_len;
	char* _in_buf = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_foo_t));
	CHECK_UNIQUE_POINTER(_tmp_buf_in, _len_buf_in);
	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);

	if (_tmp_buf_in != NULL) {
		_in_buf_in = (char*)malloc(_len_buf_in);
		if (_in_buf_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_buf_in, _tmp_buf_in, _len_buf_in);
	}
	if (_tmp_buf != NULL) {
		if ((_in_buf = (char*)malloc(_len_buf)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_buf, 0, _len_buf);
	}
	foo(_in_buf_in, _in_buf, _tmp_len);
err:
	if (_in_buf_in) free(_in_buf_in);
	if (_in_buf) {
		memcpy(_tmp_buf, _in_buf, _len_buf);
		free(_in_buf);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_hammingDistance(void* pms)
{
	ms_hammingDistance_t* ms = SGX_CAST(ms_hammingDistance_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char** _tmp_input = ms->ms_input;
	int _tmp_len_in = ms->ms_len_in;
	size_t _len_input = _tmp_len_in;
	char** _in_input = NULL;
	int* _tmp_output = ms->ms_output;

	CHECK_REF_POINTER(pms, sizeof(ms_hammingDistance_t));
	CHECK_UNIQUE_POINTER(_tmp_input, _len_input);

	if (_tmp_input != NULL) {
		_in_input = (char**)malloc(_len_input);
		if (_in_input == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_input, _tmp_input, _len_input);
	}
	hammingDistance(_in_input, _tmp_output, ms->ms_query, ms->ms_len_out, _tmp_len_in, ms->ms_rowcount);
err:
	if (_in_input) free(_in_input);

	return status;
}

static sgx_status_t SGX_CDECL sgx_euclidieanDistance(void* pms)
{
	ms_euclidieanDistance_t* ms = SGX_CAST(ms_euclidieanDistance_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char** _tmp_input = ms->ms_input;
	int _tmp_len_in = ms->ms_len_in;
	size_t _len_input = _tmp_len_in;
	char** _in_input = NULL;
	int* _tmp_output = ms->ms_output;

	CHECK_REF_POINTER(pms, sizeof(ms_euclidieanDistance_t));
	CHECK_UNIQUE_POINTER(_tmp_input, _len_input);

	if (_tmp_input != NULL) {
		_in_input = (char**)malloc(_len_input);
		if (_in_input == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_input, _tmp_input, _len_input);
	}
	euclidieanDistance(_in_input, _tmp_output, ms->ms_query, ms->ms_len_out, _tmp_len_in, ms->ms_rowcount);
err:
	if (_in_input) free(_in_input);

	return status;
}

static sgx_status_t SGX_CDECL sgx_ld(void* pms)
{
	ms_ld_t* ms = SGX_CAST(ms_ld_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char** _tmp_input = ms->ms_input;
	int _tmp_len_ldmatrix = ms->ms_len_ldmatrix;
	size_t _len_input = _tmp_len_ldmatrix;
	char** _in_input = NULL;
	char* _tmp_ldResult = ms->ms_ldResult;
	int _tmp_len_ldResult = ms->ms_len_ldResult;
	size_t _len_ldResult = _tmp_len_ldResult;
	char* _in_ldResult = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ld_t));
	CHECK_UNIQUE_POINTER(_tmp_input, _len_input);
	CHECK_UNIQUE_POINTER(_tmp_ldResult, _len_ldResult);

	if (_tmp_input != NULL) {
		_in_input = (char**)malloc(_len_input);
		if (_in_input == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_input, _tmp_input, _len_input);
	}
	if (_tmp_ldResult != NULL) {
		if ((_in_ldResult = (char*)malloc(_len_ldResult)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_ldResult, 0, _len_ldResult);
	}
	ld(_in_input, _in_ldResult, _tmp_len_ldmatrix, _tmp_len_ldResult);
err:
	if (_in_input) free(_in_input);
	if (_in_ldResult) {
		memcpy(_tmp_ldResult, _in_ldResult, _len_ldResult);
		free(_in_ldResult);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_hwe(void* pms)
{
	ms_hwe_t* ms = SGX_CAST(ms_hwe_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char** _tmp_input = ms->ms_input;
	int _tmp_len_hwematrix = ms->ms_len_hwematrix;
	size_t _len_input = _tmp_len_hwematrix;
	char** _in_input = NULL;
	char* _tmp_hweResult = ms->ms_hweResult;
	int _tmp_len_hweResult = ms->ms_len_hweResult;
	size_t _len_hweResult = _tmp_len_hweResult;
	char* _in_hweResult = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_hwe_t));
	CHECK_UNIQUE_POINTER(_tmp_input, _len_input);
	CHECK_UNIQUE_POINTER(_tmp_hweResult, _len_hweResult);

	if (_tmp_input != NULL) {
		_in_input = (char**)malloc(_len_input);
		if (_in_input == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_input, _tmp_input, _len_input);
	}
	if (_tmp_hweResult != NULL) {
		if ((_in_hweResult = (char*)malloc(_len_hweResult)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_hweResult, 0, _len_hweResult);
	}
	hwe(_in_input, _in_hweResult, _tmp_len_hwematrix, _tmp_len_hweResult);
err:
	if (_in_input) free(_in_input);
	if (_in_hweResult) {
		memcpy(_tmp_hweResult, _in_hweResult, _len_hweResult);
		free(_in_hweResult);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_catt(void* pms)
{
	ms_catt_t* ms = SGX_CAST(ms_catt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char** _tmp_input = ms->ms_input;
	int _tmp_len_cattmatrix = ms->ms_len_cattmatrix;
	size_t _len_input = _tmp_len_cattmatrix;
	char** _in_input = NULL;
	char* _tmp_cattResult = ms->ms_cattResult;
	int _tmp_len_cattResult = ms->ms_len_cattResult;
	size_t _len_cattResult = _tmp_len_cattResult;
	char* _in_cattResult = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_catt_t));
	CHECK_UNIQUE_POINTER(_tmp_input, _len_input);
	CHECK_UNIQUE_POINTER(_tmp_cattResult, _len_cattResult);

	if (_tmp_input != NULL) {
		_in_input = (char**)malloc(_len_input);
		if (_in_input == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_input, _tmp_input, _len_input);
	}
	if (_tmp_cattResult != NULL) {
		if ((_in_cattResult = (char*)malloc(_len_cattResult)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_cattResult, 0, _len_cattResult);
	}
	catt(_in_input, _in_cattResult, _tmp_len_cattmatrix, _tmp_len_cattResult);
err:
	if (_in_input) free(_in_input);
	if (_in_cattResult) {
		memcpy(_tmp_cattResult, _in_cattResult, _len_cattResult);
		free(_in_cattResult);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_fet(void* pms)
{
	ms_fet_t* ms = SGX_CAST(ms_fet_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char** _tmp_input = ms->ms_input;
	int _tmp_len_fetmatrix = ms->ms_len_fetmatrix;
	size_t _len_input = _tmp_len_fetmatrix;
	char** _in_input = NULL;
	char* _tmp_fetResult = ms->ms_fetResult;
	int _tmp_len_fetResult = ms->ms_len_fetResult;
	size_t _len_fetResult = _tmp_len_fetResult;
	char* _in_fetResult = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_fet_t));
	CHECK_UNIQUE_POINTER(_tmp_input, _len_input);
	CHECK_UNIQUE_POINTER(_tmp_fetResult, _len_fetResult);

	if (_tmp_input != NULL) {
		_in_input = (char**)malloc(_len_input);
		if (_in_input == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_input, _tmp_input, _len_input);
	}
	if (_tmp_fetResult != NULL) {
		if ((_in_fetResult = (char*)malloc(_len_fetResult)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_fetResult, 0, _len_fetResult);
	}
	fet(_in_input, _in_fetResult, _tmp_len_fetmatrix, _tmp_len_fetResult);
err:
	if (_in_input) free(_in_input);
	if (_in_fetResult) {
		memcpy(_tmp_fetResult, _in_fetResult, _len_fetResult);
		free(_in_fetResult);
	}

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv;} ecall_table[7];
} g_ecall_table = {
	7,
	{
		{(void*)(uintptr_t)sgx_foo, 0},
		{(void*)(uintptr_t)sgx_hammingDistance, 0},
		{(void*)(uintptr_t)sgx_euclidieanDistance, 0},
		{(void*)(uintptr_t)sgx_ld, 0},
		{(void*)(uintptr_t)sgx_hwe, 0},
		{(void*)(uintptr_t)sgx_catt, 0},
		{(void*)(uintptr_t)sgx_fet, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[1][7];
} g_dyn_entry_table = {
	1,
	{
		{0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_str);
		memcpy((void*)ms->ms_str, str, _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(0, ms);


	sgx_ocfree();
	return status;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
