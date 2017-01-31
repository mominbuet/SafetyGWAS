#include "isv_enclave_u.h"
#include <errno.h>

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

static sgx_status_t SGX_CDECL isv_enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL isv_enclave_create_session_ocall(void* pms)
{
	ms_create_session_ocall_t* ms = SGX_CAST(ms_create_session_ocall_t*, pms);
	ms->ms_retval = create_session_ocall(ms->ms_sid, ms->ms_dh_msg1, ms->ms_dh_msg1_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL isv_enclave_exchange_report_ocall(void* pms)
{
	ms_exchange_report_ocall_t* ms = SGX_CAST(ms_exchange_report_ocall_t*, pms);
	ms->ms_retval = exchange_report_ocall(ms->ms_sid, ms->ms_dh_msg2, ms->ms_dh_msg2_size, ms->ms_dh_msg3, ms->ms_dh_msg3_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL isv_enclave_close_session_ocall(void* pms)
{
	ms_close_session_ocall_t* ms = SGX_CAST(ms_close_session_ocall_t*, pms);
	ms->ms_retval = close_session_ocall(ms->ms_sid, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL isv_enclave_invoke_service_ocall(void* pms)
{
	ms_invoke_service_ocall_t* ms = SGX_CAST(ms_invoke_service_ocall_t*, pms);
	ms->ms_retval = invoke_service_ocall(ms->ms_pse_message_req, ms->ms_pse_message_req_size, ms->ms_pse_message_resp, ms->ms_pse_message_resp_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL isv_enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL isv_enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall((const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL isv_enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall((const void*)ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL isv_enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall((const void*)ms->ms_waiter, (const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL isv_enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall((const void**)ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[10];
} ocall_table_isv_enclave = {
	10,
	{
		(void*)(uintptr_t)isv_enclave_ocall_print_string,
		(void*)(uintptr_t)isv_enclave_create_session_ocall,
		(void*)(uintptr_t)isv_enclave_exchange_report_ocall,
		(void*)(uintptr_t)isv_enclave_close_session_ocall,
		(void*)(uintptr_t)isv_enclave_invoke_service_ocall,
		(void*)(uintptr_t)isv_enclave_sgx_oc_cpuidex,
		(void*)(uintptr_t)isv_enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)(uintptr_t)isv_enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)(uintptr_t)isv_enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)(uintptr_t)isv_enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};

sgx_status_t enclave_init_ra(sgx_enclave_id_t eid, sgx_status_t* retval, int b_pse, sgx_ra_context_t* p_context)
{
	sgx_status_t status;
	ms_enclave_init_ra_t ms;
	ms.ms_b_pse = b_pse;
	ms.ms_p_context = p_context;
	status = sgx_ecall(eid, 0, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enclave_ra_close(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context)
{
	sgx_status_t status;
	ms_enclave_ra_close_t ms;
	ms.ms_context = context;
	status = sgx_ecall(eid, 1, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t verify_att_result_mac(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint8_t* message, size_t message_size, uint8_t* mac, size_t mac_size)
{
	sgx_status_t status;
	ms_verify_att_result_mac_t ms;
	ms.ms_context = context;
	ms.ms_message = message;
	ms.ms_message_size = message_size;
	ms.ms_mac = mac;
	ms.ms_mac_size = mac_size;
	status = sgx_ecall(eid, 2, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t put_secret_data(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint8_t* p_secret, uint32_t secret_size, uint8_t* gcm_mac)
{
	sgx_status_t status;
	ms_put_secret_data_t ms;
	ms.ms_context = context;
	ms.ms_p_secret = p_secret;
	ms.ms_secret_size = secret_size;
	ms.ms_gcm_mac = gcm_mac;
	status = sgx_ecall(eid, 3, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t foo(sgx_enclave_id_t eid, char* buf_in, char* buf, int len)
{
	sgx_status_t status;
	ms_foo_t ms;
	ms.ms_buf_in = buf_in;
	ms.ms_buf = buf;
	ms.ms_len = len;
	status = sgx_ecall(eid, 4, &ocall_table_isv_enclave, &ms);
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
	status = sgx_ecall(eid, 5, &ocall_table_isv_enclave, &ms);
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
	status = sgx_ecall(eid, 6, &ocall_table_isv_enclave, &ms);
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
	status = sgx_ecall(eid, 7, &ocall_table_isv_enclave, &ms);
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
	status = sgx_ecall(eid, 8, &ocall_table_isv_enclave, &ms);
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
	status = sgx_ecall(eid, 9, &ocall_table_isv_enclave, &ms);
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
	status = sgx_ecall(eid, 10, &ocall_table_isv_enclave, &ms);
	return status;
}

sgx_status_t sgx_ra_get_ga(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, sgx_ec256_public_t* g_a)
{
	sgx_status_t status;
	ms_sgx_ra_get_ga_t ms;
	ms.ms_context = context;
	ms.ms_g_a = g_a;
	status = sgx_ecall(eid, 11, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_proc_msg2_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce)
{
	sgx_status_t status;
	ms_sgx_ra_proc_msg2_trusted_t ms;
	ms.ms_context = context;
	ms.ms_p_msg2 = (sgx_ra_msg2_t*)p_msg2;
	ms.ms_p_qe_target = (sgx_target_info_t*)p_qe_target;
	ms.ms_p_report = p_report;
	ms.ms_p_nonce = p_nonce;
	status = sgx_ecall(eid, 12, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_get_msg3_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size)
{
	sgx_status_t status;
	ms_sgx_ra_get_msg3_trusted_t ms;
	ms.ms_context = context;
	ms.ms_quote_size = quote_size;
	ms.ms_qe_report = qe_report;
	ms.ms_p_msg3 = p_msg3;
	ms.ms_msg3_size = msg3_size;
	status = sgx_ecall(eid, 13, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

