#ifndef ENCLAVE1_U_H__
#define ENCLAVE1_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));

sgx_status_t foo(sgx_enclave_id_t eid, char* buf_in, char* buf, int len);
sgx_status_t hammingDistance(sgx_enclave_id_t eid, char** input, int* output, int query, int len_out, int len_in, int rowcount);
sgx_status_t euclidieanDistance(sgx_enclave_id_t eid, char** input, int* output, int query, int len_out, int len_in, int rowcount);
sgx_status_t ld(sgx_enclave_id_t eid, char** input, char* ldResult, int len_ldmatrix, int len_ldResult);
sgx_status_t hwe(sgx_enclave_id_t eid, char** input, char* hweResult, int len_hwematrix, int len_hweResult);
sgx_status_t catt(sgx_enclave_id_t eid, char** input, char* cattResult, int len_cattmatrix, int len_cattResult);
sgx_status_t fet(sgx_enclave_id_t eid, char** input, char* fetResult, int len_fetmatrix, int len_fetResult);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
