#ifndef ENCLAVE1_T_H__
#define ENCLAVE1_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


void foo(char* buf_in, char* buf, int len);
void hammingDistance(char** input, int* output, int query, int len_out, int len_in, int rowcount);
void euclidieanDistance(char** input, int* output, int query, int len_out, int len_in, int rowcount);
void ld(char** input, char* ldResult, int len_ldmatrix, int len_ldResult);
void hwe(char** input, char* hweResult, int len_hwematrix, int len_hweResult);
void catt(char** input, char* cattResult, int len_cattmatrix, int len_cattResult);
void fet(char** input, char* fetResult, int len_fetmatrix, int len_fetResult);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
