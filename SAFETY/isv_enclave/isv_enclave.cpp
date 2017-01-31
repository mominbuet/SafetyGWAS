/**
*   Copyright(C) 2011-2015 Intel Corporation All Rights Reserved.
*
*   The source code, information  and  material ("Material") contained herein is
*   owned  by Intel Corporation or its suppliers or licensors, and title to such
*   Material remains  with Intel Corporation  or its suppliers or licensors. The
*   Material  contains proprietary information  of  Intel or  its  suppliers and
*   licensors. The  Material is protected by worldwide copyright laws and treaty
*   provisions. No  part  of  the  Material  may  be  used,  copied, reproduced,
*   modified, published, uploaded, posted, transmitted, distributed or disclosed
*   in any way  without Intel's  prior  express written  permission. No  license
*   under  any patent, copyright  or  other intellectual property rights  in the
*   Material  is  granted  to  or  conferred  upon  you,  either  expressly,  by
*   implication, inducement,  estoppel or  otherwise.  Any  license  under  such
*   intellectual  property  rights must  be express  and  approved  by  Intel in
*   writing.
*
*   *Third Party trademarks are the property of their respective owners.
*
*   Unless otherwise  agreed  by Intel  in writing, you may not remove  or alter
*   this  notice or  any other notice embedded  in Materials by Intel or Intel's
*   suppliers or licensors in any way.
*/


#include "isv_enclave_t.h"
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "string.h"
#include "sgx_tseal.h"
#include "sgx_tae_service.h"
//FROM PREVIOUS PROJECT
#include "sgx_trts.h"
//#include "user_types.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h> 
//#include <algorithm.h> 
#include <string>
#include <vector>
#include <bitset>
#include <map>
#include "BigIntegerLibrary.h"
#include <math.h>
#include <stdint.h>
//#include "fet.cpp"

/* --------for Fisher Exact Test function from : https://github.com/chrchang/stats/blob/master/fisher.c  --------*/
#define SMALLISH_EPSILON 0.00000000003
#define SMALL_EPSILON 0.0000000000001

// This helps us avoid premature floating point overflow.
#define EXACT_TEST_BIAS 0.00000000000000000000000010339757656912845935892608650874535669572651386260986328125



#ifdef _MSC_VER
#pragma warning(push)
#pragma warning ( disable:4127 )
#endif


void printf(const char *fmt, ...)
{
	char buf[BUFSIZ] = {'\0'};
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	ocall_print_string(buf);
}

// This is the public EC key of the SP. The corresponding private EC key is
// used by the SP to sign data used in the remote attestation SIGMA protocol
// to sign channel binding data in MSG2. A successful verification of the
// signature confirms the identity of the SP to the ISV app in remote
// attestation secure channel binding. The public EC key should be hardcoded in
// the enclave or delivered in a trustworthy manner. The use of a spoofed public
// EC key in the remote attestation with secure channel binding session may lead
// to a security compromise. Every different SP the enlcave communicates to
// must have a unique SP public key. Delivery of the SP public key is
// determined by the ISV. The TKE SIGMA protocl expects an Elliptical Curve key
// based on NIST P-256
static const sgx_ec256_public_t g_sp_pub_key = {
    {
        0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
        0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
        0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
        0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
    },
    {
        0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
        0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
        0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
        0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
    }
};

// Used to store the secret passed by the SP in the sample code. The
// size is forced to be 8 bytes. Expected value is
// 0x01,0x02,0x03,0x04,0x0x5,0x0x6,0x0x7
uint8_t g_secret[8] = {0};
char* mysecret = new char[930];
string g, lambda;
//uint8_t sealed_data[930];
sgx_sealed_data_t* sealed_data;


#ifdef SUPPLIED_KEY_DERIVATION

#pragma message ("Supplied key derivation function is used.")

typedef struct _hash_buffer_t
{
    uint8_t counter[4];
    sgx_ec256_dh_shared_t shared_secret;
    uint8_t algorithm_id[4];
} hash_buffer_t;

const char ID_U[] = "SGXRAENCLAVE";
const char ID_V[] = "SGXRASERVER";

// Derive two keys from shared key and key id.
bool derive_key(
    const sgx_ec256_dh_shared_t *p_shared_key,
    uint8_t key_id,
    sgx_ec_key_128bit_t *first_derived_key,
    sgx_ec_key_128bit_t *second_derived_key)
{
    sgx_status_t sgx_ret = SGX_SUCCESS;
    hash_buffer_t hash_buffer;
    sgx_sha_state_handle_t sha_context;
    sgx_sha256_hash_t key_material;

    memset(&hash_buffer, 0, sizeof(hash_buffer_t));
    /* counter in big endian  */
    hash_buffer.counter[3] = key_id;

    /*convert from little endian to big endian */
    for (size_t i = 0; i < sizeof(sgx_ec256_dh_shared_t); i++)
    {
        hash_buffer.shared_secret.s[i] = p_shared_key->s[sizeof(p_shared_key->s)-1 - i];
    }

    sgx_ret = sgx_sha256_init(&sha_context);
    if (sgx_ret != SGX_SUCCESS)
    {
        return false;
    }
    sgx_ret = sgx_sha256_update((uint8_t*)&hash_buffer, sizeof(hash_buffer_t), sha_context);
    if (sgx_ret != SGX_SUCCESS)
    {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_update((uint8_t*)&ID_U, sizeof(ID_U), sha_context);
    if (sgx_ret != SGX_SUCCESS)
    {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_update((uint8_t*)&ID_V, sizeof(ID_V), sha_context);
    if (sgx_ret != SGX_SUCCESS)
    {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_get_hash(sha_context, &key_material);
    if (sgx_ret != SGX_SUCCESS)
    {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_close(sha_context);

    static_assert(sizeof(sgx_ec_key_128bit_t)* 2 == sizeof(sgx_sha256_hash_t), "structure size mismatch.");
    memcpy(first_derived_key, &key_material, sizeof(sgx_ec_key_128bit_t));
    memcpy(second_derived_key, (uint8_t*)&key_material + sizeof(sgx_ec_key_128bit_t), sizeof(sgx_ec_key_128bit_t));

    // memset here can be optimized away by compiler, so please use memset_s on
    // windows for production code and similar functions on other OSes.
    memset(&key_material, 0, sizeof(sgx_sha256_hash_t));

    return true;
}

//isv defined key derivation function id
#define ISV_KDF_ID 2

typedef enum _derive_key_type_t
{
    DERIVE_KEY_SMK_SK = 0,
    DERIVE_KEY_MK_VK,
} derive_key_type_t;

sgx_status_t key_derivation(const sgx_ec256_dh_shared_t* shared_key,
	uint16_t kdf_id,
    sgx_ec_key_128bit_t* smk_key,
    sgx_ec_key_128bit_t* sk_key,
    sgx_ec_key_128bit_t* mk_key,
    sgx_ec_key_128bit_t* vk_key)
{
    bool derive_ret = false;

    if (NULL == shared_key)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

	if (ISV_KDF_ID != kdf_id)
    {
        //fprintf(stderr, "\nError, key derivation id mismatch in [%s].", __FUNCTION__);
		return SGX_ERROR_KDF_MISMATCH;
	}

    derive_ret = derive_key(shared_key, DERIVE_KEY_SMK_SK,
        smk_key, sk_key);
    if (derive_ret != true)
    {
        //fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
        return SGX_ERROR_UNEXPECTED;
    }

    derive_ret = derive_key(shared_key, DERIVE_KEY_MK_VK,
        mk_key, vk_key);
    if (derive_ret != true)
    {
        //fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
        return SGX_ERROR_UNEXPECTED;
    }
    return SGX_SUCCESS;
}
#else
#pragma message ("Default key derivation function is used.")
#endif

// This ecall is a wrapper of sgx_ra_init to create the trusted
// KE exchange key context needed for the remote attestation
// SIGMA API's. Input pointers aren't checked since the trusted stubs
// copy them into EPC memory.
//
// @param b_pse Indicates whether the ISV app is using the
//              platform services.
// @param p_context Pointer to the location where the returned
//                  key context is to be copied.
//
// @return Any error return from the create PSE session if b_pse
//         is true.
// @return Any error returned from the trusted key exchange API
//         for creating a key context.

sgx_status_t enclave_init_ra(
    int b_pse,
    sgx_ra_context_t *p_context)
{
    // isv enclave call to trusted key exchange library.
    sgx_status_t ret;
    if(b_pse)
    {
        int busy_retry_times = 2;
        do{
            ret = sgx_create_pse_session();
        }while (ret == SGX_ERROR_BUSY && busy_retry_times--);
        if (ret != SGX_SUCCESS)
            return ret;
    }
#ifdef SUPPLIED_KEY_DERIVATION
    ret = sgx_ra_init_ex(&g_sp_pub_key, b_pse, key_derivation, p_context);
#else
    ret = sgx_ra_init(&g_sp_pub_key, b_pse, p_context);
#endif
    if(b_pse)
    {
        sgx_close_pse_session();
        return ret;
    }
    return ret;
}


// Closes the tKE key context used during the SIGMA key
// exchange.
//
// @param context The trusted KE library key context.
//
// @return Return value from the key context close API

sgx_status_t SGXAPI enclave_ra_close(
    sgx_ra_context_t context)
{
    sgx_status_t ret;
    ret = sgx_ra_close(context);
    return ret;
}


// Verify the mac sent in att_result_msg from the SP using the
// MK key. Input pointers aren't checked since the trusted stubs
// copy them into EPC memory.
//
//
// @param context The trusted KE library key context.
// @param p_message Pointer to the message used to produce MAC
// @param message_size Size in bytes of the message.
// @param p_mac Pointer to the MAC to compare to.
// @param mac_size Size in bytes of the MAC
//
// @return SGX_ERROR_INVALID_PARAMETER - MAC size is incorrect.
// @return Any error produced by tKE  API to get SK key.
// @return Any error produced by the AESCMAC function.
// @return SGX_ERROR_MAC_MISMATCH - MAC compare fails.

sgx_status_t verify_att_result_mac(sgx_ra_context_t context,
                                   uint8_t* p_message,
                                   size_t message_size,
                                   uint8_t* p_mac,
                                   size_t mac_size)
{
    sgx_status_t ret;
    sgx_ec_key_128bit_t mk_key;

    if(mac_size != sizeof(sgx_mac_t))
    {
        ret = SGX_ERROR_INVALID_PARAMETER;
        return ret;
    }
    if(message_size > UINT32_MAX)
    {
        ret = SGX_ERROR_INVALID_PARAMETER;
        return ret;
    }

    do {
        uint8_t mac[SGX_CMAC_MAC_SIZE] = {0};

        ret = sgx_ra_get_keys(context, SGX_RA_KEY_MK, &mk_key);
        if(SGX_SUCCESS != ret)
        {
            break;
        }
        ret = sgx_rijndael128_cmac_msg(&mk_key,
                                       p_message,
                                       (uint32_t)message_size,
                                       &mac);
        if(SGX_SUCCESS != ret)
        {
            break;
        }
        if(0 == consttime_memequal(p_mac, mac, sizeof(mac)))
        {
            ret = SGX_ERROR_MAC_MISMATCH;
            break;
        }

    }
    while(0);

    return ret;
}


// Generate a secret information for the SP encrypted with SK.
// Input pointers aren't checked since the trusted stubs copy
// them into EPC memory.
//
// @param context The trusted KE library key context.
// @param p_secret Message containing the secret.
// @param secret_size Size in bytes of the secret message.
// @param p_gcm_mac The pointer the the AESGCM MAC for the
//                 message.
//
// @return SGX_ERROR_INVALID_PARAMETER - secret size if
//         incorrect.
// @return Any error produced by tKE  API to get SK key.
// @return Any error produced by the AESGCM function.
// @return SGX_ERROR_UNEXPECTED - the secret doesn't match the
//         expected value.

sgx_status_t put_secret_data(
    sgx_ra_context_t context,
    uint8_t *p_secret,
    uint32_t secret_size,
    uint8_t *p_gcm_mac)
{
    sgx_status_t ret = SGX_SUCCESS;
    sgx_ec_key_128bit_t sk_key;

    do {
        if(secret_size != 8)
        {
            //ret = SGX_ERROR_INVALID_PARAMETER;
            //break;
        }

        ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
        if(SGX_SUCCESS != ret)
        {
            break;
        }

        uint8_t aes_gcm_iv[12] = {0};
        ret = sgx_rijndael128GCM_decrypt(&sk_key,
                                         p_secret,
                                         secret_size,
                                         (uint8_t*)mysecret,//&g_secret[0],
                                         &aes_gcm_iv[0],
                                         12,
                                         NULL,
                                         0,
                                         (sgx_aes_gcm_128bit_tag_t *)
										 (p_gcm_mac))
										 //(const sgx_aes_gcm_128bit_tag_t *)
								          //p_secret + secret_size)
										   ;

        uint32_t i;
        bool secret_match = true;
        for(i=0;i<secret_size;i++)
        {
            if(g_secret[i] != i)
            {
                //secret_match = false;
            }
        }

        if(!secret_match)
        {
            ret = SGX_ERROR_UNEXPECTED;
        }

        // Once the server has the shared secret, it should be sealed to
        // persistent storage for future use. This will prevents having to
        // perform remote attestation until the secret goes stale. Once the
        // enclave is created again, the secret can be unsealed.
		//sgx_sealed_data_t* 
		/*
		sgx_status_t sealStatus;

		sealStatus = sgx_seal_data(0, NULL, 930, (uint8_t*)mysecret,
            930, sealed_data);

		uint8_t enclaveSealedSecret[930];
		uint8_t unsealed_data[930];
		//memcpy(enclaveSealedSecret, sealed_data, 930);
		uint32_t unsealedLength =930;
	
		sealStatus = sgx_unseal_data(sealed_data, NULL, 0, (uint8_t*)&unsealed_data, &unsealedLength);

		/*char* unsealedDecrypt = new char[930];
		sealStatus = sgx_rijndael128GCM_decrypt(&sk_key,
			                             unsealed_data,
                                         930,
                                         (uint8_t*)unsealedDecrypt,//&g_secret[0],
                                         &aes_gcm_iv[0],
                                         12,
                                         NULL,
                                         0,
                                         (sgx_aes_gcm_128bit_tag_t *)
										 (p_gcm_mac))
										 //(const sgx_aes_gcm_128bit_tag_t *)
								          //p_secret + secret_size)
										   ;
		 
		 if (sealStatus != SGX_SUCCESS)
		 {
			 printf("\n could not seal %d \n", sealStatus);
			 printf("unsealed data %s \n",unsealed_data);
		 }
		 */

    } while(0);

	//printf("Shared secret %d %d %d %d %d %d %d %d \n",g_secret[0], g_secret[1], g_secret[2], g_secret[3], g_secret[4], g_secret[5], g_secret[6], g_secret[7]);
	//printf("Secret size %d \n", secret_size);
	string privateKeys(mysecret);
	int pos = privateKeys.find("-");
	g = privateKeys.substr(0, pos);
	lambda = privateKeys.substr(pos+1, strlen(mysecret)+1);

	//printf("mysecret %s \n", mysecret);
	//printf("g is %s \n", g.c_str());
	//printf("lambda is %s \n", lambda.c_str());

    return ret;
}



unsigned long long int factorial(unsigned long long int n) 
{
	if (n == 0)
		return 1;
	return n * factorial(n - 1);
}

std::string decryption1(char* CT, string gstr,string lambdastr)
{
	BigInteger g = stringToBigInteger(gstr);
	//std::string lambdaString("");
	BigUnsigned lambda = stringToBigUnsigned(lambdastr);

	std::string nString("9593607111946713583637349021265853784815765173385176303469907380421600017694920194456746044180428105843855618758545175731860381728503640872298025089899723");
	BigUnsigned n = stringToBigUnsigned(nString);

	BigUnsigned nSquare = n*n;
	//printf("Started from Enclave\n");



	//std::string cipherString("43735173856029611568442515340040338973765522024252082316032076385986617053089886752926708989233889578831940845942385592153895942552156209392481325308186780691620385855198994821671794143517814662528038016041565888708512232513867588340210126188506600216223286142866839767691175010591527471406190716529361189423");
	//printf("Incoming:%s\n",(CT));

	std::string cipherString(CT);

	BigInteger cipher = stringToBigInteger(cipherString);
	BigInteger one =  BigInteger(1);
	//u = (L(g^lambda mod n^2))^(-1) mod n
	//BigInteger u = g.modPow(lambda, nsquare).subtract(BigInteger.ONE).divide(n).modInverse(n);
	//BigInteger u1 = ;
	//BigInteger u2 = (BigInteger)modexp(g, lambda, nSquare) - BigInteger(1);
	//BigInteger u3 =( (BigInteger)modexp(g, lambda, nSquare) -one) / n;
	BigInteger u4 = modinv(( (BigInteger)modexp(g, lambda, nSquare) -one) / n, n);

	//BigInteger d1 = ;
	//BigInteger d2 = (BigInteger)modexp(cipher, lambda, nSquare) - one;
	//BigInteger d3 = ((BigInteger)modexp(cipher, lambda, nSquare) - one)/n;
	//BigInteger d4 = (((BigInteger)modexp(cipher, lambda, nSquare) - one)/n)*u4;
	BigInteger d5 = ((((BigInteger)modexp(cipher, lambda, nSquare) - one)/n)*u4)%n;

	//std::string decrypted = bigIntegerToString(d5);

	//printf("decrypted in enclave %d %s \n", strlen(decrypted.c_str()), decrypted.c_str());

	return bigIntegerToString(d5);
}

std::string decryption(char* CT,string gstr, string lambdastr)
{
	BigInteger g(5);
	std::string lambdaString("4796803555973356791818674510632926892407882586692588151734953690210800008847361929847747957286738245101626609080248778027443254771400903147580088452877004");
	BigUnsigned lambda = stringToBigUnsigned(lambdaString);

	std::string nString("9593607111946713583637349021265853784815765173385176303469907380421600017694920194456746044180428105843855618758545175731860381728503640872298025089899723");
	BigUnsigned n = stringToBigUnsigned(nString);

	BigUnsigned nSquare = n*n;
	//printf("Started from Enclave\n");
	//std::string cipherString("43735173856029611568442515340040338973765522024252082316032076385986617053089886752926708989233889578831940845942385592153895942552156209392481325308186780691620385855198994821671794143517814662528038016041565888708512232513867588340210126188506600216223286142866839767691175010591527471406190716529361189423");
	//printf("Incoming:%s\n",(CT));

	std::string cipherString(CT);

	BigInteger cipher = stringToBigInteger(cipherString);

	//u = (L(g^lambda mod n^2))^(-1) mod n
	//BigInteger u = g.modPow(lambda, nsquare).subtract(BigInteger.ONE).divide(n).modInverse(n);
	BigInteger u1 = modexp(g, lambda, nSquare);
	BigInteger u2 = u1 - BigInteger(1);
	BigInteger u3 = u2 / n;
	BigInteger u4 = modinv(u3, n);

	BigInteger d1 = modexp(cipher, lambda, nSquare);
	BigInteger d2 = d1 - BigInteger(1);
	BigInteger d3 = d2/n;
	BigInteger d4 = d3*u4;
	BigInteger d5 = d4%n;

	std::string decrypted = bigIntegerToString(d5);

	//printf("decrypted in enclave %d %s \n", strlen(decrypted.c_str()), decrypted.c_str());

	return decrypted;
}

void foo(char* buf_in,char *buf, int len)
{
	BigInteger g(5);
	std::string lambdaString("681187336829861685983477976074309227114055423213861997326044753839039065994675872317693880166082865602230364912349325536661776647701497008450899024296700");
	BigUnsigned lambda = stringToBigUnsigned(lambdaString);

	std::string nString("6811873368298616859834779760743092271140554232138619973260447538390390659946923911334832555109330889332724359014932390928355480544102778783662820806617091");
	BigUnsigned n = stringToBigUnsigned(nString);

	BigUnsigned nSquare = n*n;
	printf("Started from Enclave\n");
	//std::string cipherString("43735173856029611568442515340040338973765522024252082316032076385986617053089886752926708989233889578831940845942385592153895942552156209392481325308186780691620385855198994821671794143517814662528038016041565888708512232513867588340210126188506600216223286142866839767691175010591527471406190716529361189423");
	printf("Incoming:%s\n",(buf_in));

	std::string cipherString(buf_in);

	BigInteger cipher = stringToBigInteger(cipherString);

	//u = (L(g^lambda mod n^2))^(-1) mod n
	//BigInteger u = g.modPow(lambda, nsquare).subtract(BigInteger.ONE).divide(n).modInverse(n);
	BigInteger u1 = modexp(g, lambda, nSquare);
	BigInteger u2 = u1 - BigInteger(1);
	BigInteger u3 = u2 / n;
	BigInteger u4 = modinv(u3, n);

	BigInteger d1 = modexp(cipher, lambda, nSquare);
	BigInteger d2 = d1 - BigInteger(1);
	BigInteger d3 = d2/n;
	BigInteger d4 = d3*u4;
	BigInteger d5 = d4%n;

	std::string decrypted = bigIntegerToString(d5);

	const char *secret = decrypted.c_str();//"Hello Enclave!";
	//char *secret = strcpy((char*)malloc(decrypted.length()+1), decrypted.c_str());
	if (len > strlen(secret))
	{
		memcpy(buf, secret, strlen(secret) + 1);
	}
	//printf("%s \n", secret);



}

void ld(char** input, char* ldResult, int len_ldmatrix, int len_ldResult)
{
	//printf("%s \n", input[0]);
	//printf("%s \n", input[1]);
	//printf("%s \n", input[2]);
	//printf("%s \n", input[3]);

	//All four encrypted genotype counts are in enclave now
	//TO DO

	//1. decrypt the four values
	std::string N_AB_ds = decryption(input[0],g,lambda);
	//printf("decrypted string %s \n", N_AB_ds.c_str());
	int N_AB_d = atoi(decryption(input[0], g, lambda).c_str());
	//printf("%d \n", N_AB_d);

	int N_Ab_d = atoi(decryption(input[1], g, lambda).c_str());
	//printf("%d \n", N_Ab_d);

	int N_aB_d = atoi(decryption(input[2], g, lambda).c_str());
	//printf("%d \n", N_aB_d);

	int N_ab_d = atoi(decryption(input[3], g, lambda).c_str());
	//printf("%d \n", N_ab_d);

	//2. sum these values to find N

	int N = N_AB_d + N_Ab_d + N_aB_d + N_ab_d;
	//printf("%d \n", N);

	//3. find the frequencies P_AB, P_Ab, P_aB, P_ab.
	float P_AB = N_AB_d/(float)N;
	float P_Ab = N_Ab_d/(float)N;
	float P_aB = N_aB_d/(float)N;
	float P_ab = N_ab_d/(float)N;
	//printf("%f %f %f %f \n", P_AB, P_Ab, P_aB, P_ab);

	//4. Calculate D = P_AB*P_ab - P_aB*P_Ab
	float D = P_AB*P_ab - P_aB*P_Ab;
	//printf("%f \n", D);

	//5. P_A = P_AB + P_Ab, P_a = BigInteger.one - P_A
	//   P_B = P_AB + P_aB, P_b = BigInteger.one - P_B
	float P_A = P_AB + P_Ab;
	float P_B = P_AB + P_aB;

	//printf("%f %f \n", P_A, P_B);

	//6. If D>0, D_max = min(P_A*P_b, P_a*P_B)
	//	 else,   D_max = min(P_A*P_B, P_a*P_b)
	float D_max;
	if(D > 0)
	{
		D_max = min(P_A*(1 - P_B), (1 - P_A)*P_B);
		//printf("greater than 0 \n");
	}
	else
	{
		D_max = min(P_A*P_B, (1 - P_A)*(1 - P_B));
		//printf("not greater than 0 \n");
	}


	//7. D' = D/D_max
	float D_prime = abs(D/D_max);
	//printf("%f \n", D_prime);

	//memcpy(ldResult, input[0], strlen(input[0]) + 1);
	memcpy(ldResult, (D_prime == 0.0)? "0":"1", 1);


}

void hwe(char** input, char* hweResult, int len_hwematrix, int len_hweResult)
{
	//printf("HWE processing starts \n");
	//step 1. decrypt n_AA, n_Aa, n_aa and get sum n
	int N_AA_d = atoi(decryption(input[0], g, lambda).c_str());
	//printf("%d \n", N_AA_d);
	int N_Aa_d = atoi(decryption(input[1], g, lambda).c_str());
	//printf("%d \n", N_Aa_d);
	int N_aa_d = atoi(decryption(input[2], g, lambda).c_str());
	//printf("%d \n", N_aa_d);

	int N = N_AA_d + N_Aa_d + N_aa_d;

	//step 2. P_A = (n_AA/n)+(0.5*(n_Aa/n))  Then, P_a = 1 - P_A
	float P_A = (N_AA_d/(float)N) + (0.5*(N_Aa_d/N));
	float P_a = 1.0 - P_A;
	//printf("%f %f \n", P_A, P_a);

	//step 3. Expected counts of AA= nP_A^2, Aa=2*nP_AP_a, aa=nP_a^2
	float N_AA_exp = N*P_A*P_A;
	float N_Aa_exp = 2*N*P_A*P_a;
	float N_aa_exp = N*P_a*P_a;

	//step 4. Pearson goodness of fit test 
	float chi_square = (pow((N_AA_d - N_AA_exp), 2)/N_AA_exp) + (pow((N_Aa_d - N_Aa_exp), 2)/N_Aa_exp) + (pow((N_aa_d - N_aa_exp), 2)/N_aa_exp);
	//printf("%f \n", chi_square);

	//0 for hwe doe not hold, 1 for hwe holds
	//hweResult = (chi_square >= 3.841)? "0":"1";
	memcpy(hweResult, (chi_square >= 3.841)? "0":"1", 1);

	//printf("%s \n",hweResult);

}

void catt(char** input, char* cattResult, int len_cattmatrix, int len_cattResult)
{
	//printf("CATT processing starts \n");

	int N_AA_case_d = atoi(decryption(input[0], g, lambda).c_str());
	//printf("%d \n", N_AA_case_d);
	int N_Aa_case_d = atoi(decryption(input[1], g, lambda).c_str());
	//printf("%d \n", N_Aa_case_d);
	int N_aa_case_d = atoi(decryption(input[2], g, lambda).c_str());
	//printf("%d \n", N_aa_case_d);

	int case_sum = N_AA_case_d + N_Aa_case_d + N_aa_case_d;

	int N_AA_control_d = atoi(decryption(input[3], g, lambda).c_str());
	//printf("%d \n", N_AA_control_d);
	int N_Aa_control_d = atoi(decryption(input[4], g, lambda).c_str());
	//printf("%d \n", N_Aa_control_d);
	int N_aa_control_d = atoi(decryption(input[5], g, lambda).c_str());
	//printf("%d \n", N_aa_control_d);

	int control_sum = N_AA_control_d + N_Aa_control_d + N_aa_control_d;
	int sum = case_sum + control_sum;

	//codominant model (0,1,2) 
	float weight1 = 0.0;
	float weight2 = 1.0;
	float weight3 = 2.0;

	float T = weight1*(N_AA_control_d*case_sum - N_AA_case_d*control_sum) +
		weight2*(N_Aa_control_d*case_sum - N_Aa_case_d*control_sum) +
		weight3*(N_aa_control_d*case_sum - N_aa_case_d*control_sum);

	int AA_sum = N_AA_case_d + N_AA_control_d;
	int Aa_sum = N_Aa_case_d + N_Aa_control_d;
	int aa_sum = N_aa_case_d + N_aa_control_d;

	float var_T = ((control_sum * case_sum)/(float)(control_sum + case_sum))*
		(
		(
		(weight1*weight1)*(sum - AA_sum)*AA_sum +
		(weight2*weight2)*(sum - Aa_sum)*Aa_sum +
		(weight3*weight3)*(sum - aa_sum)*aa_sum 
		)
		-
		(2*((pow(weight1, 2)*pow(weight2, 2)*AA_sum*Aa_sum) + ((pow(weight2, 2)*pow(weight2, 2)*Aa_sum*aa_sum))))
		);
	float chi_square = (T*T)/var_T;
	//printf("%f", chi_square);

	//df = 1, critical chi_square value = 3.841
	//null hypothesis: no trend 
	//cattResult = (chi_square >= 3.841)? "1":"0";
	memcpy(cattResult, (chi_square >= 3.841)? "1":"0", 1);
	//printf("%s \n",cattResult);

}

int32_t fisher23_tailsum(double* base_probp, double* saved12p, double* saved13p, double* saved22p, double* saved23p, double *totalp, uint32_t* tie_ctp, uint32_t right_side) {
	double total = 0;
	double cur_prob = *base_probp;
	double tmp12 = *saved12p;
	double tmp13 = *saved13p;
	double tmp22 = *saved22p;
	double tmp23 = *saved23p;
	double tmps12;
	double tmps13;
	double tmps22;
	double tmps23;
	double prev_prob;
	// identify beginning of tail
	if (right_side) {
		if (cur_prob > EXACT_TEST_BIAS) {
			prev_prob = tmp13 * tmp22;
			while (prev_prob > 0.5) {
				tmp12 += 1;
				tmp23 += 1;
				cur_prob *= prev_prob / (tmp12 * tmp23);
				tmp13 -= 1;
				tmp22 -= 1;
				if (cur_prob <= EXACT_TEST_BIAS) {
					break;
				}
				prev_prob = tmp13 * tmp22;
			}
			*base_probp = cur_prob;
			tmps12 = tmp12;
			tmps13 = tmp13;
			tmps22 = tmp22;
			tmps23 = tmp23;
		} else {
			tmps12 = tmp12;
			tmps13 = tmp13;
			tmps22 = tmp22;
			tmps23 = tmp23;
			while (1) {
				prev_prob = cur_prob;
				tmp13 += 1;
				tmp22 += 1;
				cur_prob *= (tmp12 * tmp23) / (tmp13 * tmp22);
				if (cur_prob < prev_prob) {
					return 1;
				}
				tmp12 -= 1;
				tmp23 -= 1;
				if (cur_prob > (1 - 2 * SMALLISH_EPSILON) * EXACT_TEST_BIAS) {
					// throw in extra (1 - SMALL_EPSILON) multiplier to prevent rounding
					// errors from causing this to keep going when the left-side test
					// stopped
					if (cur_prob > (1 - SMALL_EPSILON) * EXACT_TEST_BIAS) {
						break;
					}
					*tie_ctp += 1;
				}
				total += cur_prob;
			}
			prev_prob = cur_prob;
			cur_prob = *base_probp;
			*base_probp = prev_prob;
		}
	} else {
		if (cur_prob > EXACT_TEST_BIAS) {
			prev_prob = tmp12 * tmp23;
			while (prev_prob > 0.5) {
				tmp13 += 1;
				tmp22 += 1;
				cur_prob *= prev_prob / (tmp13 * tmp22);
				tmp12 -= 1;
				tmp23 -= 1;
				if (cur_prob <= EXACT_TEST_BIAS) {
					break;
				}
				prev_prob = tmp12 * tmp23;
			}
			*base_probp = cur_prob;
			tmps12 = tmp12;
			tmps13 = tmp13;
			tmps22 = tmp22;
			tmps23 = tmp23;
		} else {
			tmps12 = tmp12;
			tmps13 = tmp13;
			tmps22 = tmp22;
			tmps23 = tmp23;
			while (1) {
				prev_prob = cur_prob;
				tmp12 += 1;
				tmp23 += 1;
				cur_prob *= (tmp13 * tmp22) / (tmp12 * tmp23);
				if (cur_prob < prev_prob) {
					return 1;
				}
				tmp13 -= 1;
				tmp22 -= 1;
				if (cur_prob > (1 - 2 * SMALLISH_EPSILON) * EXACT_TEST_BIAS) {
					if (cur_prob > EXACT_TEST_BIAS) {
						break;
					}
					*tie_ctp += 1;
				}
				total += cur_prob;
			}
			prev_prob = cur_prob;
			cur_prob = *base_probp;
			*base_probp = prev_prob;
		}
	}
	*saved12p = tmp12;
	*saved13p = tmp13;
	*saved22p = tmp22;
	*saved23p = tmp23;
	if (cur_prob > (1 - 2 * SMALLISH_EPSILON) * EXACT_TEST_BIAS) {
		if (cur_prob > EXACT_TEST_BIAS) {
			// even most extreme table on this side is too probable
			*totalp = 0;
			return 0;
		}
		*tie_ctp += 1;
	}
	// sum tail to floating point precision limit
	if (right_side) {
		prev_prob = total;
		total += cur_prob;
		while (total > prev_prob) {
			tmps12 += 1;
			tmps23 += 1;
			cur_prob *= (tmps13 * tmps22) / (tmps12 * tmps23);
			tmps13 -= 1;
			tmps22 -= 1;
			prev_prob = total;
			total += cur_prob;
		}
	} else {
		prev_prob = total;
		total += cur_prob;
		while (total > prev_prob) {
			tmps13 += 1;
			tmps22 += 1;
			cur_prob *= (tmps12 * tmps23) / (tmps13 * tmps22);
			tmps12 -= 1;
			tmps23 -= 1;
			prev_prob = total;
			total += cur_prob;
		}
	}
	*totalp = total;
	return 0;
}

double fisher23(uint32_t m11, uint32_t m12, uint32_t m13, uint32_t m21, uint32_t m22, uint32_t m23, uint32_t midp) {
	// 2x3 Fisher-Freeman-Halton exact test p-value calculation.
	// The number of tables involved here is still small enough that the network
	// algorithm (and the improved variants thereof that I've seen) are
	// suboptimal; a 2-dimensional version of the SNPHWE2 strategy has higher
	// performance.
	// 2x4, 2x5, and 3x3 should also be practical with this method, but beyond
	// that I doubt it's worth the trouble.
	// Complexity of approach is O(n^{df/2}), where n is number of observations.
	double cur_prob = (1 - SMALLISH_EPSILON) * EXACT_TEST_BIAS;
	double tprob = cur_prob;
	double cprob = 0;
	double dyy = 0;
	uint32_t tie_ct = 1;
	uint32_t dir = 0; // 0 = forwards, 1 = backwards
	double base_probl;
	double base_probr;
	double orig_base_probl;
	double orig_base_probr;
	double orig_row_prob;
	double row_prob;
	uint32_t uii;
	uint32_t ujj;
	uint32_t ukk;
	double cur11;
	double cur21;
	double savedl12;
	double savedl13;
	double savedl22;
	double savedl23;
	double savedr12;
	double savedr13;
	double savedr22;
	double savedr23;
	double orig_savedl12;
	double orig_savedl13;
	double orig_savedl22;
	double orig_savedl23;
	double orig_savedr12;
	double orig_savedr13;
	double orig_savedr22;
	double orig_savedr23;
	double tmp12;
	double tmp13;
	double tmp22;
	double tmp23;
	double dxx;
	double preaddp;
	// Ensure m11 + m21 <= m12 + m22 <= m13 + m23.
	uii = m11 + m21;
	ujj = m12 + m22;
	if (uii > ujj) {
		ukk = m11;
		m11 = m12;
		m12 = ukk;
		ukk = m21;
		m21 = m22;
		m22 = ukk;
		ukk = uii;
		uii = ujj;
		ujj = ukk;
	}
	ukk = m13 + m23;
	if (ujj > ukk) {
		ujj = ukk;
		ukk = m12;
		m12 = m13;
		m13 = ukk;
		ukk = m22;
		m22 = m23;
		m23 = ukk;
	}
	if (uii > ujj) {
		ukk = m11;
		m11 = m12;
		m12 = ukk;
		ukk = m21;
		m21 = m22;
		m22 = ukk;
	}
	// Ensure majority of probability mass is in front of m11.
	if ((((uint64_t)m11) * (m22 + m23)) > (((uint64_t)m21) * (m12 + m13))) {
		ukk = m11;
		m11 = m21;
		m21 = ukk;
		ukk = m12;
		m12 = m22;
		m22 = ukk;
		ukk = m13;
		m13 = m23;
		m23 = ukk;
	}
	if ((((uint64_t)m12) * m23) > (((uint64_t)m13) * m22)) {
		base_probr = cur_prob;
		savedr12 = m12;
		savedr13 = m13;
		savedr22 = m22;
		savedr23 = m23;
		tmp12 = savedr12;
		tmp13 = savedr13;
		tmp22 = savedr22;
		tmp23 = savedr23;
		// m12 and m23 must be nonzero
		dxx = tmp12 * tmp23;
		do {
			tmp13 += 1;
			tmp22 += 1;
			cur_prob *= dxx / (tmp13 * tmp22);
			tmp12 -= 1;
			tmp23 -= 1;
			if (cur_prob <= EXACT_TEST_BIAS) {
				if (cur_prob > (1 - 2 * SMALLISH_EPSILON) * EXACT_TEST_BIAS) {
					tie_ct++;
				}
				tprob += cur_prob;
				break;
			}
			cprob += cur_prob;
			if (cprob == INFINITY) {
				return 0;
			}
			dxx = tmp12 * tmp23;
			// must enforce tmp12 >= 0 and tmp23 >= 0 since we're saving these
		} while (dxx > 0.5);
		savedl12 = tmp12;
		savedl13 = tmp13;
		savedl22 = tmp22;
		savedl23 = tmp23;
		base_probl = cur_prob;
		do {
			tmp13 += 1;
			tmp22 += 1;
			cur_prob *= (tmp12 * tmp23) / (tmp13 * tmp22);
			tmp12 -= 1;
			tmp23 -= 1;
			preaddp = tprob;
			tprob += cur_prob;
		} while (tprob > preaddp);
		tmp12 = savedr12;
		tmp13 = savedr13;
		tmp22 = savedr22;
		tmp23 = savedr23;
		cur_prob = base_probr;
		do {
			tmp12 += 1;
			tmp23 += 1;
			cur_prob *= (tmp13 * tmp22) / (tmp12 * tmp23);
			tmp13 -= 1;
			tmp22 -= 1;
			preaddp = tprob;
			tprob += cur_prob;
		} while (tprob > preaddp);
	} else {
		base_probl = cur_prob;
		savedl12 = m12;
		savedl13 = m13;
		savedl22 = m22;
		savedl23 = m23;
		if (!((((uint64_t)m12) * m23) + (((uint64_t)m13) * m22))) {
			base_probr = cur_prob;
			savedr12 = savedl12;
			savedr13 = savedl13;
			savedr22 = savedl22;
			savedr23 = savedl23;
		} else {
			tmp12 = savedl12;
			tmp13 = savedl13;
			tmp22 = savedl22;
			tmp23 = savedl23;
			dxx = tmp13 * tmp22;
			do {
				tmp12 += 1;
				tmp23 += 1;
				cur_prob *= dxx / (tmp12 * tmp23);
				tmp13 -= 1;
				tmp22 -= 1;
				if (cur_prob <= EXACT_TEST_BIAS) {
					if (cur_prob > (1 - 2 * SMALLISH_EPSILON) * EXACT_TEST_BIAS) {
						tie_ct++;
					}
					tprob += cur_prob;
					break;
				}
				cprob += cur_prob;
				if (cprob == INFINITY) {
					return 0;
				}
				dxx = tmp13 * tmp22;
			} while (dxx > 0.5);
			savedr12 = tmp12;
			savedr13 = tmp13;
			savedr22 = tmp22;
			savedr23 = tmp23;
			base_probr = cur_prob;
			do {
				tmp12 += 1;
				tmp23 += 1;
				cur_prob *= (tmp13 * tmp22) / (tmp12 * tmp23);
				tmp13 -= 1;
				tmp22 -= 1;
				preaddp = tprob;
				tprob += cur_prob;
			} while (tprob > preaddp);
			tmp12 = savedl12;
			tmp13 = savedl13;
			tmp22 = savedl22;
			tmp23 = savedl23;
			cur_prob = base_probl;
			do {
				tmp13 += 1;
				tmp22 += 1;
				cur_prob *= (tmp12 * tmp23) / (tmp13 * tmp22);
				tmp12 -= 1;
				tmp23 -= 1;
				preaddp = tprob;
				tprob += cur_prob;
			} while (tprob > preaddp);
		}
	}
	row_prob = tprob + cprob;
	orig_base_probl = base_probl;
	orig_base_probr = base_probr;
	orig_row_prob = row_prob;
	orig_savedl12 = savedl12;
	orig_savedl13 = savedl13;
	orig_savedl22 = savedl22;
	orig_savedl23 = savedl23;
	orig_savedr12 = savedr12;
	orig_savedr13 = savedr13;
	orig_savedr22 = savedr22;
	orig_savedr23 = savedr23;
	for (; dir < 2; dir++) {
		cur11 = m11;
		cur21 = m21;
		if (dir) {
			base_probl = orig_base_probl;
			base_probr = orig_base_probr;
			row_prob = orig_row_prob;
			savedl12 = orig_savedl12;
			savedl13 = orig_savedl13;
			savedl22 = orig_savedl22;
			savedl23 = orig_savedl23;
			savedr12 = orig_savedr12;
			savedr13 = orig_savedr13;
			savedr22 = orig_savedr22;
			savedr23 = orig_savedr23;
			ukk = m11;
			if (ukk > m22 + m23) {
				ukk = m22 + m23;
			}
		} else {
			ukk = m21;
			if (ukk > m12 + m13) {
				ukk = m12 + m13;
			}
		}
		ukk++;
		while (--ukk) {
			if (dir) {
				cur21 += 1;
				if (savedl23) {
					savedl13 += 1;
					row_prob *= (cur11 * (savedl22 + savedl23)) / (cur21 * (savedl12 + savedl13));
					base_probl *= (cur11 * savedl23) / (cur21 * savedl13);
					savedl23 -= 1;
				} else {
					savedl12 += 1;
					row_prob *= (cur11 * (savedl22 + savedl23)) / (cur21 * (savedl12 + savedl13));
					base_probl *= (cur11 * savedl22) / (cur21 * savedl12);
					savedl22 -= 1;
				}
				cur11 -= 1;
			} else {
				cur11 += 1;
				if (savedl12) {
					savedl22 += 1;
					row_prob *= (cur21 * (savedl12 + savedl13)) / (cur11 * (savedl22 + savedl23));
					base_probl *= (cur21 * savedl12) / (cur11 * savedl22);
					savedl12 -= 1;
				} else {
					savedl23 += 1;
					row_prob *= (cur21 * (savedl12 + savedl13)) / (cur11 * (savedl22 + savedl23));
					base_probl *= (cur21 * savedl13) / (cur11 * savedl23);
					savedl13 -= 1;
				}
				cur21 -= 1;
			}
			if (fisher23_tailsum(&base_probl, &savedl12, &savedl13, &savedl22, &savedl23, &dxx, &tie_ct, 0)) {
				break;
			}
			tprob += dxx;
			if (dir) {
				if (savedr22) {
					savedr12 += 1;
					base_probr *= ((cur11 + 1) * savedr22) / (cur21 * savedr12);
					savedr22 -= 1;
				} else {
					savedr13 += 1;
					base_probr *= ((cur11 + 1) * savedr23) / (cur21 * savedr13);
					savedr23 -= 1;
				}
			} else {
				if (savedr13) {
					savedr23 += 1;
					base_probr *= ((cur21 + 1) * savedr13) / (cur11 * savedr23);
					savedr13 -= 1;
				} else {
					savedr22 += 1;
					base_probr *= ((cur21 + 1) * savedr12) / (cur11 * savedr22);
					savedr12 -= 1;
				}
			}
			fisher23_tailsum(&base_probr, &savedr12, &savedr13, &savedr22, &savedr23, &dyy, &tie_ct, 1);
			tprob += dyy;
			cprob += row_prob - dxx - dyy;
			if (cprob == INFINITY) {
				return 0;
			}
		}
		if (!ukk) {
			continue;
		}
		savedl12 += savedl13;
		savedl22 += savedl23;
		if (dir) {
			while (1) {
				preaddp = tprob;
				tprob += row_prob;
				if (tprob <= preaddp) {
					break;
				}
				cur21 += 1;
				savedl12 += 1;
				row_prob *= (cur11 * savedl22) / (cur21 * savedl12);
				cur11 -= 1;
				savedl22 -= 1;
			}
		} else {
			while (1) {
				preaddp = tprob;
				tprob += row_prob;
				if (tprob <= preaddp) {
					break;
				}
				cur11 += 1;
				savedl22 += 1;
				row_prob *= (cur21 * savedl12) / (cur11 * savedl22);
				cur21 -= 1;
				savedl12 -= 1;
			}
		}
	}
	if (!midp) {
		return tprob / (tprob + cprob);
	} else {
		return (tprob - ((1 - SMALLISH_EPSILON) * EXACT_TEST_BIAS * 0.5) * ((int32_t)tie_ct)) / (tprob + cprob);
	}
}


void fet(char** input, char* fetResult, int len_cattmatrix, int len_fetResult)
{
	//printf("FET processing starts \n");

	int N_AA_case_d = atoi(decryption(input[0], g, lambda).c_str());
	//printf("%d \n", N_AA_case_d);
	int N_Aa_case_d = atoi(decryption(input[1], g, lambda).c_str());
	//printf("%d \n", N_Aa_case_d);
	int N_aa_case_d = atoi(decryption(input[2], g, lambda).c_str());
	//printf("%d \n", N_aa_case_d);

	int case_sum = N_AA_case_d + N_Aa_case_d + N_aa_case_d;

	int N_AA_control_d = atoi(decryption(input[3], g, lambda).c_str());
	//printf("%d \n", N_AA_control_d);
	int N_Aa_control_d = atoi(decryption(input[4], g, lambda).c_str());
	//printf("%d \n", N_Aa_control_d);
	int N_aa_control_d = atoi(decryption(input[5], g, lambda).c_str());
	//printf("%d \n", N_aa_control_d);

	int control_sum = N_AA_control_d + N_Aa_control_d + N_aa_control_d;
	int sum = case_sum + control_sum;


	int AA_sum = N_AA_case_d + N_AA_control_d;
	int Aa_sum = N_Aa_case_d + N_Aa_control_d;
	int aa_sum = N_aa_case_d + N_aa_control_d;

	//int lob = factorial(case_sum)*factorial(control_sum) * factorial(AA_sum) * factorial(Aa_sum) * factorial(aa_sum);
	//int hor = factorial(N_AA_control_d) * factorial(N_Aa_control_d) * factorial(N_aa_control_d) * factorial(N_AA_case_d) * factorial(N_Aa_case_d) * factorial(N_aa_case_d) * factorial(sum);
	int denominator = factorial(5)* factorial(4)*factorial(3)*factorial(3)*factorial(3);
	int numerator = factorial(1)*factorial(2)*factorial(2)*factorial(2)*factorial(1)*factorial(1)*factorial(19);
	//float p_value = fisher23(70,20,10,40,30,30,0);  //denominator/(float)numerator;
	//float p_value = fisher23(0,3,2,6,5,1,0);

	float p_value = fisher23(N_AA_control_d, N_Aa_control_d, N_aa_control_d, N_AA_case_d, N_Aa_case_d, N_aa_case_d, 0);

	//float p_value = (factorial(case_sum) * factorial(control_sum) * factorial(AA_sum) * factorial(Aa_sum) * factorial(aa_sum)) / (float)(factorial(N_AA_control_d) * factorial(N_Aa_control_d)
	//* factorial(N_aa_control_d) * factorial(N_AA_case_d) * factorial(N_Aa_case_d) * factorial(N_aa_case_d) * factorial(sum));
	//float p_value = (double)(factorial(20) * factorial(2) * factorial(1) * factorial(2) * factorial(2)) / (double)(factorial(3) * factorial(4)
	//* factorial(4) * factorial(4) * factorial(4) * factorial(4) * factorial(4));

	//printf("%f \n", p_value);


	//df = 1, critical chi_square value = 3.841
	//null hypothesis: no statistical association between genotype and disease
	//fetResult = (p_value < 0.05)? "1":"0";
	memcpy(fetResult, (p_value < 0.05)? "1":"0", 1);
	//printf("%s \n",fetResult);

}


/*
bool* ConvertToBinary(int n)
{
int i=0,r;
bool arr[17];
while(n!=0)
{
r = n%2;
arr[i++] = (r==1);
n /= 2;
}
return arr;
}*/

void hammingDistance(char** input,int* output,  int query, int limit,int lenth_input,int rows)
{
	BigInteger g(5);
	BigUnsigned lambda = stringToBigUnsigned("681187336829861685983477976074309227114055423213861997326044753839039065994675872317693880166082865602230364912349325536661776647701497008450899024296700");
	BigUnsigned n = stringToBigUnsigned("6811873368298616859834779760743092271140554232138619973260447538390390659946923911334832555109330889332724359014932390928355480544102778783662820806617091");
	BigUnsigned nSquare = n*n;
	BigInteger u4 = modinv((((BigInteger)modexp(g, lambda, nSquare)) - BigInteger(1)) / n, n);
	int** features = new int*[rows];
	printf("running for%d query%d\n",rows,query);

	for(int i = 0; i < rows; i++){
		BigInteger cipher = stringToBigInteger(input[i]);
		BigInteger d5 = ((((BigInteger) modexp(cipher, lambda, nSquare)) - BigInteger(1))/n*u4)%n;
		const char *secret = bigIntegerToString(d5).c_str();
		int num= atoi( secret );
		int r,j=0 ;
		features[i] = new int[17];
		//printf("feature now1");
		while(num!=0){
			r = num%2;
			features[i][j++] = r;
			num /= 2;
		}
		while (j<17)
		{
			features[i][j++]=0;
		}
		printf("%d-%s:",i,secret);
		for (int k = 16; k >=0 ; k--)
		{
			printf("%d",features[i][k]);
		}
		printf("\n");
	}
	int* query_features = features[query];
	std::multimap<int,int> items;
	//distance portion
	for (int i = 0; i < rows; i++)
	{
		if(i==query)continue;
		int mismatch=0;
		//int* tmp = ;
		for (int j= 0; j < 17; j++)
		{
			//printf("%d-%d,",tmp[j],query_features[j]);
			if(query_features[j]!=features[i][j])
				mismatch++;
		}
		items.insert(std::pair<int,int>(mismatch,i));
		//similarity[i] = mismatch;
		//printf("%d:%d\n",i,mismatch);
		//free(tmp);
	}
	int tmp=0,i=0,j=0;
	int* results = new int[limit];
	for (std::multimap<int,int>::iterator it=items.begin(); it!=items.end(); ++it){
		//printf("%d:%d\n",(*it).first,(*it).second);
		results[j++]=(*it).second;
		if(tmp!=(*it).first)
			i++;
		if(i>=limit)
			break;
	}

	//std::sort(items.begin(), items.end(), value_comparer);
	//memcpy(output, results, limit*4);
	//output= results;
	memcpy(output, results, sizeof(output)*limit);
	/*for (int i = 0; i < limit; i++)
	{
	printf("%d,",output[i]);
	}

	printf("\n ended from sgx %d",sizeof(output));*/

}

void euclidieanDistance(char** input,int* output,  int query, int limit,int lenth_input,int rows)
{
	BigInteger g(5);
	BigUnsigned lambda = stringToBigUnsigned("681187336829861685983477976074309227114055423213861997326044753839039065994675872317693880166082865602230364912349325536661776647701497008450899024296700");
	BigUnsigned n = stringToBigUnsigned("6811873368298616859834779760743092271140554232138619973260447538390390659946923911334832555109330889332724359014932390928355480544102778783662820806617091");
	BigUnsigned nSquare = n*n;
	BigInteger u4 = modinv((((BigInteger)modexp(g, lambda, nSquare)) - BigInteger(1)) / n, n);
	int** features = new int*[rows];
	printf("running for%d query%d\n",rows,query);

	for(int i = 0; i < rows; i++){
		BigInteger cipher = stringToBigInteger(input[i]);
		BigInteger d5 = ((((BigInteger) modexp(cipher, lambda, nSquare)) - BigInteger(1))/n*u4)%n;
		const char *secret = bigIntegerToString(d5).c_str();
		int num= atoi( secret );
		int r,j=0 ;
		features[i] = new int[17];
		//printf("feature now1");
		while(num!=0){
			r = num%2;
			features[i][j++] = r;
			num /= 2;
		}
		while (j<17)
		{
			features[i][j++]=0;
		}
		printf("%d-%s:",i,secret);
		for (int k = 16; k >=0 ; k--)
		{
			printf("%d",features[i][k]);
		}
		printf("\n");
	}
	int* query_features = features[query];

	//distance portion
	std::multimap<double,int> items;
	for (int i = 0; i < rows; i++)
	{
		if(i==query)continue;
		double mismatch=0.0;
		//int* tmp = ;
		for (int j= 0; j < 17; j++)
		{
			mismatch = (query_features[j]-features[i][j])*(query_features[j]-features[i][j]);
		}
		items.insert(std::pair<int,int>(std::sqrt(mismatch),i));
		//similarity[i] = mismatch;
		//printf("%d:%d\n",i,mismatch);
		//free(tmp);
	}
	int tmp=0,i=0,j=0;
	int* results = new int[limit];
	for (std::multimap<double,int>::iterator it=items.begin(); it!=items.end(); ++it){
		//printf("%d:%d\n",(*it).first,(*it).second);
		results[j++]=(*it).second;
		if(tmp!=(*it).first)
			i++;
		if(i>=limit)
			break;
	}

	memcpy(output, results, sizeof(output)*limit);
	/*for (int i = 0; i < limit; i++)
	{
	printf("%d,",output[i]);
	}

	printf("\n ended from sgx %d",sizeof(output));*/

}

#ifdef _MSC_VER
    #pragma warning(pop)
#endif
