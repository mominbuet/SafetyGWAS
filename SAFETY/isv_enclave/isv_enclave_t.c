#include "isv_enclave_t.h"

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


typedef struct ms_enclave_init_ra_t {
	sgx_status_t ms_retval;
	int ms_b_pse;
	sgx_ra_context_t* ms_p_context;
} ms_enclave_init_ra_t;

typedef struct ms_enclave_ra_close_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
} ms_enclave_ra_close_t;

typedef struct ms_verify_att_result_mac_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint8_t* ms_message;
	size_t ms_message_size;
	uint8_t* ms_mac;
	size_t ms_mac_size;
} ms_verify_att_result_mac_t;

typedef struct ms_put_secret_data_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint8_t* ms_p_secret;
	uint32_t ms_secret_size;
	uint8_t* ms_gcm_mac;
} ms_put_secret_data_t;

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

typedef struct ms_sgx_ra_get_ga_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	sgx_ec256_public_t* ms_g_a;
} ms_sgx_ra_get_ga_t;

typedef struct ms_sgx_ra_proc_msg2_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	sgx_ra_msg2_t* ms_p_msg2;
	sgx_target_info_t* ms_p_qe_target;
	sgx_report_t* ms_p_report;
	sgx_quote_nonce_t* ms_p_nonce;
} ms_sgx_ra_proc_msg2_trusted_t;

typedef struct ms_sgx_ra_get_msg3_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint32_t ms_quote_size;
	sgx_report_t* ms_qe_report;
	sgx_ra_msg3_t* ms_p_msg3;
	uint32_t ms_msg3_size;
} ms_sgx_ra_get_msg3_trusted_t;

typedef struct ms_ocall_print_string_t {
	char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_create_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t* ms_sid;
	uint8_t* ms_dh_msg1;
	uint32_t ms_dh_msg1_size;
	uint32_t ms_timeout;
} ms_create_session_ocall_t;

typedef struct ms_exchange_report_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint8_t* ms_dh_msg2;
	uint32_t ms_dh_msg2_size;
	uint8_t* ms_dh_msg3;
	uint32_t ms_dh_msg3_size;
	uint32_t ms_timeout;
} ms_exchange_report_ocall_t;

typedef struct ms_close_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint32_t ms_timeout;
} ms_close_session_ocall_t;

typedef struct ms_invoke_service_ocall_t {
	sgx_status_t ms_retval;
	uint8_t* ms_pse_message_req;
	uint32_t ms_pse_message_req_size;
	uint8_t* ms_pse_message_resp;
	uint32_t ms_pse_message_resp_size;
	uint32_t ms_timeout;
} ms_invoke_service_ocall_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	void* ms_waiter;
	void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#pragma warning(disable: 4200)
#endif

static sgx_status_t SGX_CDECL sgx_enclave_init_ra(void* pms)
{
	ms_enclave_init_ra_t* ms = SGX_CAST(ms_enclave_init_ra_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ra_context_t* _tmp_p_context = ms->ms_p_context;
	size_t _len_p_context = sizeof(*_tmp_p_context);
	sgx_ra_context_t* _in_p_context = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_enclave_init_ra_t));
	CHECK_UNIQUE_POINTER(_tmp_p_context, _len_p_context);

	if (_tmp_p_context != NULL) {
		if ((_in_p_context = (sgx_ra_context_t*)malloc(_len_p_context)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_context, 0, _len_p_context);
	}
	ms->ms_retval = enclave_init_ra(ms->ms_b_pse, _in_p_context);
err:
	if (_in_p_context) {
		memcpy(_tmp_p_context, _in_p_context, _len_p_context);
		free(_in_p_context);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_ra_close(void* pms)
{
	ms_enclave_ra_close_t* ms = SGX_CAST(ms_enclave_ra_close_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_enclave_ra_close_t));

	ms->ms_retval = enclave_ra_close(ms->ms_context);


	return status;
}

static sgx_status_t SGX_CDECL sgx_verify_att_result_mac(void* pms)
{
	ms_verify_att_result_mac_t* ms = SGX_CAST(ms_verify_att_result_mac_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_message = ms->ms_message;
	size_t _tmp_message_size = ms->ms_message_size;
	size_t _len_message = _tmp_message_size;
	uint8_t* _in_message = NULL;
	uint8_t* _tmp_mac = ms->ms_mac;
	size_t _tmp_mac_size = ms->ms_mac_size;
	size_t _len_mac = _tmp_mac_size;
	uint8_t* _in_mac = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_verify_att_result_mac_t));
	CHECK_UNIQUE_POINTER(_tmp_message, _len_message);
	CHECK_UNIQUE_POINTER(_tmp_mac, _len_mac);

	if (_tmp_message != NULL) {
		_in_message = (uint8_t*)malloc(_len_message);
		if (_in_message == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_message, _tmp_message, _len_message);
	}
	if (_tmp_mac != NULL) {
		_in_mac = (uint8_t*)malloc(_len_mac);
		if (_in_mac == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_mac, _tmp_mac, _len_mac);
	}
	ms->ms_retval = verify_att_result_mac(ms->ms_context, _in_message, _tmp_message_size, _in_mac, _tmp_mac_size);
err:
	if (_in_message) free(_in_message);
	if (_in_mac) free(_in_mac);

	return status;
}

static sgx_status_t SGX_CDECL sgx_put_secret_data(void* pms)
{
	ms_put_secret_data_t* ms = SGX_CAST(ms_put_secret_data_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_p_secret = ms->ms_p_secret;
	uint32_t _tmp_secret_size = ms->ms_secret_size;
	size_t _len_p_secret = _tmp_secret_size;
	uint8_t* _in_p_secret = NULL;
	uint8_t* _tmp_gcm_mac = ms->ms_gcm_mac;
	size_t _len_gcm_mac = 16 * sizeof(*_tmp_gcm_mac);
	uint8_t* _in_gcm_mac = NULL;

	if (16 > (SIZE_MAX / sizeof(*_tmp_gcm_mac))) {
		status = SGX_ERROR_INVALID_PARAMETER;
		goto err;
	}

	CHECK_REF_POINTER(pms, sizeof(ms_put_secret_data_t));
	CHECK_UNIQUE_POINTER(_tmp_p_secret, _len_p_secret);
	CHECK_UNIQUE_POINTER(_tmp_gcm_mac, _len_gcm_mac);

	if (_tmp_p_secret != NULL) {
		_in_p_secret = (uint8_t*)malloc(_len_p_secret);
		if (_in_p_secret == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_p_secret, _tmp_p_secret, _len_p_secret);
	}
	if (_tmp_gcm_mac != NULL) {
		_in_gcm_mac = (uint8_t*)malloc(_len_gcm_mac);
		if (_in_gcm_mac == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_gcm_mac, _tmp_gcm_mac, _len_gcm_mac);
	}
	ms->ms_retval = put_secret_data(ms->ms_context, _in_p_secret, _tmp_secret_size, _in_gcm_mac);
err:
	if (_in_p_secret) free(_in_p_secret);
	if (_in_gcm_mac) free(_in_gcm_mac);

	return status;
}

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

static sgx_status_t SGX_CDECL sgx_sgx_ra_get_ga(void* pms)
{
	ms_sgx_ra_get_ga_t* ms = SGX_CAST(ms_sgx_ra_get_ga_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec256_public_t* _tmp_g_a = ms->ms_g_a;
	size_t _len_g_a = sizeof(*_tmp_g_a);
	sgx_ec256_public_t* _in_g_a = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_get_ga_t));
	CHECK_UNIQUE_POINTER(_tmp_g_a, _len_g_a);

	if (_tmp_g_a != NULL) {
		if ((_in_g_a = (sgx_ec256_public_t*)malloc(_len_g_a)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_g_a, 0, _len_g_a);
	}
	ms->ms_retval = sgx_ra_get_ga(ms->ms_context, _in_g_a);
err:
	if (_in_g_a) {
		memcpy(_tmp_g_a, _in_g_a, _len_g_a);
		free(_in_g_a);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_proc_msg2_trusted(void* pms)
{
	ms_sgx_ra_proc_msg2_trusted_t* ms = SGX_CAST(ms_sgx_ra_proc_msg2_trusted_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ra_msg2_t* _tmp_p_msg2 = ms->ms_p_msg2;
	size_t _len_p_msg2 = sizeof(*_tmp_p_msg2);
	sgx_ra_msg2_t* _in_p_msg2 = NULL;
	sgx_target_info_t* _tmp_p_qe_target = ms->ms_p_qe_target;
	size_t _len_p_qe_target = sizeof(*_tmp_p_qe_target);
	sgx_target_info_t* _in_p_qe_target = NULL;
	sgx_report_t* _tmp_p_report = ms->ms_p_report;
	size_t _len_p_report = sizeof(*_tmp_p_report);
	sgx_report_t* _in_p_report = NULL;
	sgx_quote_nonce_t* _tmp_p_nonce = ms->ms_p_nonce;
	size_t _len_p_nonce = sizeof(*_tmp_p_nonce);
	sgx_quote_nonce_t* _in_p_nonce = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_proc_msg2_trusted_t));
	CHECK_UNIQUE_POINTER(_tmp_p_msg2, _len_p_msg2);
	CHECK_UNIQUE_POINTER(_tmp_p_qe_target, _len_p_qe_target);
	CHECK_UNIQUE_POINTER(_tmp_p_report, _len_p_report);
	CHECK_UNIQUE_POINTER(_tmp_p_nonce, _len_p_nonce);

	if (_tmp_p_msg2 != NULL) {
		_in_p_msg2 = (sgx_ra_msg2_t*)malloc(_len_p_msg2);
		if (_in_p_msg2 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_p_msg2, _tmp_p_msg2, _len_p_msg2);
	}
	if (_tmp_p_qe_target != NULL) {
		_in_p_qe_target = (sgx_target_info_t*)malloc(_len_p_qe_target);
		if (_in_p_qe_target == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_p_qe_target, _tmp_p_qe_target, _len_p_qe_target);
	}
	if (_tmp_p_report != NULL) {
		if ((_in_p_report = (sgx_report_t*)malloc(_len_p_report)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_report, 0, _len_p_report);
	}
	if (_tmp_p_nonce != NULL) {
		if ((_in_p_nonce = (sgx_quote_nonce_t*)malloc(_len_p_nonce)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_nonce, 0, _len_p_nonce);
	}
	ms->ms_retval = sgx_ra_proc_msg2_trusted(ms->ms_context, (const sgx_ra_msg2_t*)_in_p_msg2, (const sgx_target_info_t*)_in_p_qe_target, _in_p_report, _in_p_nonce);
err:
	if (_in_p_msg2) free((void*)_in_p_msg2);
	if (_in_p_qe_target) free((void*)_in_p_qe_target);
	if (_in_p_report) {
		memcpy(_tmp_p_report, _in_p_report, _len_p_report);
		free(_in_p_report);
	}
	if (_in_p_nonce) {
		memcpy(_tmp_p_nonce, _in_p_nonce, _len_p_nonce);
		free(_in_p_nonce);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_get_msg3_trusted(void* pms)
{
	ms_sgx_ra_get_msg3_trusted_t* ms = SGX_CAST(ms_sgx_ra_get_msg3_trusted_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_report_t* _tmp_qe_report = ms->ms_qe_report;
	size_t _len_qe_report = sizeof(*_tmp_qe_report);
	sgx_report_t* _in_qe_report = NULL;
	sgx_ra_msg3_t* _tmp_p_msg3 = ms->ms_p_msg3;

	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_get_msg3_trusted_t));
	CHECK_UNIQUE_POINTER(_tmp_qe_report, _len_qe_report);

	if (_tmp_qe_report != NULL) {
		_in_qe_report = (sgx_report_t*)malloc(_len_qe_report);
		if (_in_qe_report == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_qe_report, _tmp_qe_report, _len_qe_report);
	}
	ms->ms_retval = sgx_ra_get_msg3_trusted(ms->ms_context, ms->ms_quote_size, _in_qe_report, _tmp_p_msg3, ms->ms_msg3_size);
err:
	if (_in_qe_report) free(_in_qe_report);

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv;} ecall_table[14];
} g_ecall_table = {
	14,
	{
		{(void*)(uintptr_t)sgx_enclave_init_ra, 0},
		{(void*)(uintptr_t)sgx_enclave_ra_close, 0},
		{(void*)(uintptr_t)sgx_verify_att_result_mac, 0},
		{(void*)(uintptr_t)sgx_put_secret_data, 0},
		{(void*)(uintptr_t)sgx_foo, 0},
		{(void*)(uintptr_t)sgx_hammingDistance, 0},
		{(void*)(uintptr_t)sgx_euclidieanDistance, 0},
		{(void*)(uintptr_t)sgx_ld, 0},
		{(void*)(uintptr_t)sgx_hwe, 0},
		{(void*)(uintptr_t)sgx_catt, 0},
		{(void*)(uintptr_t)sgx_fet, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_get_ga, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_proc_msg2_trusted, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_get_msg3_trusted, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[10][14];
} g_dyn_entry_table = {
	10,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
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

sgx_status_t SGX_CDECL create_session_ocall(sgx_status_t* retval, uint32_t* sid, uint8_t* dh_msg1, uint32_t dh_msg1_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_sid = sizeof(*sid);
	size_t _len_dh_msg1 = dh_msg1_size;

	ms_create_session_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_create_session_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (sid != NULL && sgx_is_within_enclave(sid, _len_sid)) ? _len_sid : 0;
	ocalloc_size += (dh_msg1 != NULL && sgx_is_within_enclave(dh_msg1, _len_dh_msg1)) ? _len_dh_msg1 : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_create_session_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_create_session_ocall_t));

	if (sid != NULL && sgx_is_within_enclave(sid, _len_sid)) {
		ms->ms_sid = (uint32_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_sid);
		memset(ms->ms_sid, 0, _len_sid);
	} else if (sid == NULL) {
		ms->ms_sid = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (dh_msg1 != NULL && sgx_is_within_enclave(dh_msg1, _len_dh_msg1)) {
		ms->ms_dh_msg1 = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_dh_msg1);
		memset(ms->ms_dh_msg1, 0, _len_dh_msg1);
	} else if (dh_msg1 == NULL) {
		ms->ms_dh_msg1 = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_dh_msg1_size = dh_msg1_size;
	ms->ms_timeout = timeout;
	status = sgx_ocall(1, ms);

	if (retval) *retval = ms->ms_retval;
	if (sid) memcpy((void*)sid, ms->ms_sid, _len_sid);
	if (dh_msg1) memcpy((void*)dh_msg1, ms->ms_dh_msg1, _len_dh_msg1);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL exchange_report_ocall(sgx_status_t* retval, uint32_t sid, uint8_t* dh_msg2, uint32_t dh_msg2_size, uint8_t* dh_msg3, uint32_t dh_msg3_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_dh_msg2 = dh_msg2_size;
	size_t _len_dh_msg3 = dh_msg3_size;

	ms_exchange_report_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_exchange_report_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (dh_msg2 != NULL && sgx_is_within_enclave(dh_msg2, _len_dh_msg2)) ? _len_dh_msg2 : 0;
	ocalloc_size += (dh_msg3 != NULL && sgx_is_within_enclave(dh_msg3, _len_dh_msg3)) ? _len_dh_msg3 : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_exchange_report_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_exchange_report_ocall_t));

	ms->ms_sid = sid;
	if (dh_msg2 != NULL && sgx_is_within_enclave(dh_msg2, _len_dh_msg2)) {
		ms->ms_dh_msg2 = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_dh_msg2);
		memcpy(ms->ms_dh_msg2, dh_msg2, _len_dh_msg2);
	} else if (dh_msg2 == NULL) {
		ms->ms_dh_msg2 = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_dh_msg2_size = dh_msg2_size;
	if (dh_msg3 != NULL && sgx_is_within_enclave(dh_msg3, _len_dh_msg3)) {
		ms->ms_dh_msg3 = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_dh_msg3);
		memset(ms->ms_dh_msg3, 0, _len_dh_msg3);
	} else if (dh_msg3 == NULL) {
		ms->ms_dh_msg3 = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_dh_msg3_size = dh_msg3_size;
	ms->ms_timeout = timeout;
	status = sgx_ocall(2, ms);

	if (retval) *retval = ms->ms_retval;
	if (dh_msg3) memcpy((void*)dh_msg3, ms->ms_dh_msg3, _len_dh_msg3);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL close_session_ocall(sgx_status_t* retval, uint32_t sid, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_close_session_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_close_session_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_close_session_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_close_session_ocall_t));

	ms->ms_sid = sid;
	ms->ms_timeout = timeout;
	status = sgx_ocall(3, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL invoke_service_ocall(sgx_status_t* retval, uint8_t* pse_message_req, uint32_t pse_message_req_size, uint8_t* pse_message_resp, uint32_t pse_message_resp_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pse_message_req = pse_message_req_size;
	size_t _len_pse_message_resp = pse_message_resp_size;

	ms_invoke_service_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_invoke_service_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (pse_message_req != NULL && sgx_is_within_enclave(pse_message_req, _len_pse_message_req)) ? _len_pse_message_req : 0;
	ocalloc_size += (pse_message_resp != NULL && sgx_is_within_enclave(pse_message_resp, _len_pse_message_resp)) ? _len_pse_message_resp : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_invoke_service_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_invoke_service_ocall_t));

	if (pse_message_req != NULL && sgx_is_within_enclave(pse_message_req, _len_pse_message_req)) {
		ms->ms_pse_message_req = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_pse_message_req);
		memcpy(ms->ms_pse_message_req, pse_message_req, _len_pse_message_req);
	} else if (pse_message_req == NULL) {
		ms->ms_pse_message_req = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_pse_message_req_size = pse_message_req_size;
	if (pse_message_resp != NULL && sgx_is_within_enclave(pse_message_resp, _len_pse_message_resp)) {
		ms->ms_pse_message_resp = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_pse_message_resp);
		memset(ms->ms_pse_message_resp, 0, _len_pse_message_resp);
	} else if (pse_message_resp == NULL) {
		ms->ms_pse_message_resp = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_pse_message_resp_size = pse_message_resp_size;
	ms->ms_timeout = timeout;
	status = sgx_ocall(4, ms);

	if (retval) *retval = ms->ms_retval;
	if (pse_message_resp) memcpy((void*)pse_message_resp, ms->ms_pse_message_resp, _len_pse_message_resp);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(*cpuinfo);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	ocalloc_size += (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) ? _len_cpuinfo : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));

	if (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		memcpy(ms->ms_cpuinfo, cpuinfo, _len_cpuinfo);
	} else if (cpuinfo == NULL) {
		ms->ms_cpuinfo = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(5, ms);

	if (cpuinfo) memcpy((void*)cpuinfo, ms->ms_cpuinfo, _len_cpuinfo);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));

	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(6, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	status = sgx_ocall(7, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(8, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(*waiters);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) ? _len_waiters : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));

	if (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) {
		ms->ms_waiters = (void**)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		memcpy((void*)ms->ms_waiters, waiters, _len_waiters);
	} else if (waiters == NULL) {
		ms->ms_waiters = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(9, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
