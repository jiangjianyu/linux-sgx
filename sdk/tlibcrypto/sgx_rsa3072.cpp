/*
 * Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include "sgx_ecc256_common.h"

#ifdef __cplusplus
extern "C" {
#endif
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/platform.h"
#include "mbedtls/rsa.h"
#include "mbedtls/pk.h"
#ifdef __cplusplus
}
#endif

extern "C" void TEE_GenerateRandom(void *randomBuffer, uint32_t randomBufferLen);

#define SHA_SIZE_BIT  256

sgx_status_t sgx_rsa3072_sign(const uint8_t * p_data, 
    uint32_t data_size, 
    const sgx_rsa3072_private_key_t * p_private, 
    sgx_rsa3072_signature_t * p_signature)
{
    (void)(p_data);
    (void)(data_size);
    (void)(p_private);
    (void)(p_signature);
    return SGX_SUCCESS;
}

sgx_status_t sgx_rsa3072_verify(const uint8_t *p_data,
    uint32_t data_size,
    const sgx_rsa3072_public_key_t *p_public,
    const sgx_rsa3072_signature_t *p_signature,
	sgx_rsa_result_t *p_result)
{
    (void)(p_data);
    (void)(data_size);
    (void)(p_public);
    (void)(p_signature);
    (void)(p_result);
    return SGX_SUCCESS;
}

#define EXPONENT 65537

int r(void *data, unsigned char *output, size_t size) {
    ((void) data);
    TEE_GenerateRandom(output, (uint32_t)size);
    return 0;
}

extern "C" sgx_status_t sgx_rsa_keygen (int bitsRSA, char* pubKey, char* privKey) {
    int ret;
    mbedtls_rsa_context rsa;
    mbedtls_pk_context rsa_key_ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const mbedtls_pk_info_t* rsa_key_info_ptr = mbedtls_pk_info_from_type(MBEDTLS_PK_RSA);

    memset(pubKey, 0, bitsRSA);
    memset(privKey, 0, bitsRSA);

    mbedtls_ctr_drbg_init( &ctr_drbg );

    mbedtls_entropy_init( &entropy );

    mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256 );

    if( ( ret = mbedtls_rsa_gen_key( &rsa, r, &ctr_drbg, bitsRSA,
                             EXPONENT ) ) != 0 )
    {
        goto exit;
    }

    mbedtls_pk_init(&rsa_key_ctx);
    if ((ret = mbedtls_pk_setup(&rsa_key_ctx, rsa_key_info_ptr)) != 0) {
        goto exit;
    }
    rsa_key_ctx.pk_ctx = &rsa;

    if ((ret = mbedtls_pk_write_pubkey_pem(&rsa_key_ctx, (unsigned char*) pubKey, bitsRSA)) < 0) {
        goto exit;
    }

    // memcpy(pubKey, pub_buf + bitsRSA - ret, ret);

    if ((ret = mbedtls_pk_write_key_pem(&rsa_key_ctx, (unsigned char*) privKey, bitsRSA)) < 0) {
        goto exit;
    }

    // memcpy(privKey, priv_buf + bitsRSA - ret, ret);

exit:

    mbedtls_rsa_free( &rsa );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    if (ret < 0) {
        return (sgx_status_t)ret;
    }

    return SGX_SUCCESS;
}

//This function will do the rsa oaep encryption with input src[0:src_len] and put the output to buffer dst
//The function will assume that buffer src_len is no more than PVE_RSAOAEP_ENCRYPT_MAXLEN and the buffer size of dst is at least PVE_RSA_KEY_BITS
extern "C" sgx_status_t sgx_rsa_oaep_encrypt(const uint8_t *src, uint32_t src_len, char* pubKey, uint8_t* dst)
{
    int ret;
    mbedtls_pk_context rsa_key_ctx;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_rsa_context* rsa_context;

    mbedtls_pk_init(&rsa_key_ctx);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    if ((ret = mbedtls_pk_parse_public_key(&rsa_key_ctx, (const unsigned char*)pubKey, strlen(pubKey) + 1)) < 0 ) {
        goto exit;
    }

    rsa_context = mbedtls_pk_rsa(rsa_key_ctx);

    mbedtls_rsa_set_padding(rsa_context, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

    if ((ret = mbedtls_rsa_rsaes_oaep_encrypt(rsa_context, r, &ctr_drbg, MBEDTLS_RSA_PUBLIC, NULL, 0, src_len, src, dst)) < 0) {
        goto exit;
    }


exit:
    mbedtls_pk_free(&rsa_key_ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);

    return (sgx_status_t)(-ret);
}

extern "C" sgx_status_t sgx_rsa_oaep_decrypt(const uint8_t *src, int* dst_len, char* privKey, uint8_t* dst)
{
    int ret;
    mbedtls_pk_context rsa_key_ctx;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_rsa_context* rsa_context;

    mbedtls_pk_init(&rsa_key_ctx);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    if ((ret = mbedtls_pk_parse_key(&rsa_key_ctx, (const unsigned char*)privKey, strlen(privKey) + 1, NULL, 0)) < 0 ) {
        goto exit;
    }

    rsa_context = mbedtls_pk_rsa(rsa_key_ctx);
    mbedtls_rsa_set_padding(rsa_context, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

    if ((ret = mbedtls_rsa_rsaes_oaep_decrypt(rsa_context, r, &ctr_drbg, MBEDTLS_RSA_PRIVATE, NULL, 0, (size_t*)dst_len, src, dst, *dst_len)) < 0) {
        goto exit;
    }


exit:
    mbedtls_pk_free(&rsa_key_ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);

    return (sgx_status_t)(-ret);
}
