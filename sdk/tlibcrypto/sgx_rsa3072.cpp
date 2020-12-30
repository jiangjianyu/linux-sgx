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
#include "ippcore.h"

#define SHA_SIZE_BIT  256

sgx_status_t sgx_rsa3072_sign(const uint8_t * p_data, 
    uint32_t data_size, 
    const sgx_rsa3072_private_key_t * p_private, 
    sgx_rsa3072_signature_t * p_signature)
{
    if ((p_data == NULL) || (data_size < 1) || (p_private == NULL) ||
        (p_signature == NULL) )
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    IppStatus ipp_ret = ippStsNoErr;
    IppHashAlgId hash_alg = ippHashAlg_SHA256;

    IppsRSAPrivateKeyState* p_rsa_privatekey_ctx = NULL;
    Ipp8u *temp_buff = NULL;

    IppsBigNumState* p_prikey_mod_bn = NULL;
    IppsBigNumState* p_prikey_exp_bn = NULL;

    do
    {
        // Initializa IPP BN from the private key 
        ipp_ret = sgx_ipp_newBN((const Ipp32u *)p_private->mod, sizeof(p_private->mod), &p_prikey_mod_bn);
        ERROR_BREAK(ipp_ret);

        ipp_ret = sgx_ipp_newBN((const Ipp32u *)p_private->exp, sizeof(p_private->exp), &p_prikey_exp_bn);
        ERROR_BREAK(ipp_ret);

        // allocate private key context
        int private_key_ctx_size = 0;

        ipp_ret = ippsRSA_GetSizePrivateKeyType1(SGX_RSA3072_KEY_SIZE * 8, SGX_RSA3072_PRI_EXP_SIZE * 8,
            &private_key_ctx_size);
        ERROR_BREAK(ipp_ret);

        p_rsa_privatekey_ctx = (IppsRSAPrivateKeyState*)malloc(private_key_ctx_size);
        if (!p_rsa_privatekey_ctx) {
            ipp_ret = ippStsMemAllocErr;
            break;
        }

        // initialize the private key context
        ipp_ret = ippsRSA_InitPrivateKeyType1(SGX_RSA3072_KEY_SIZE * 8, SGX_RSA3072_PRI_EXP_SIZE * 8,
            p_rsa_privatekey_ctx, private_key_ctx_size);
        ERROR_BREAK(ipp_ret);

        ipp_ret = ippsRSA_SetPrivateKeyType1(p_prikey_mod_bn, p_prikey_exp_bn, p_rsa_privatekey_ctx);
        ERROR_BREAK(ipp_ret);

        // allocate temp buffer for RSA calculation 
        int private_key_buffer_size = 0;

        ipp_ret = ippsRSA_GetBufferSizePrivateKey(&private_key_buffer_size, p_rsa_privatekey_ctx);
        ERROR_BREAK(ipp_ret);

        temp_buff = (Ipp8u*)malloc(private_key_buffer_size);
        if (!temp_buff) {
            ipp_ret = ippStsMemAllocErr;
            break;
        }

        // sign the data buffer
        ipp_ret = ippsRSASign_PKCS1v15(p_data, data_size, *p_signature, p_rsa_privatekey_ctx, NULL, hash_alg, temp_buff);

    } while (0);

    sgx_ipp_secure_free_BN(p_prikey_mod_bn, sizeof(p_private->mod));
    sgx_ipp_secure_free_BN(p_prikey_exp_bn, sizeof(p_private->exp));
    SAFE_FREE(p_rsa_privatekey_ctx);
    SAFE_FREE(temp_buff);

    switch (ipp_ret)
    {
    case ippStsNoErr: return SGX_SUCCESS;
    case ippStsNoMemErr:
    case ippStsMemAllocErr: return SGX_ERROR_OUT_OF_MEMORY;
    case ippStsNullPtrErr:
    case ippStsLengthErr:
    case ippStsOutOfRangeErr:
    case ippStsSizeErr:
    case ippStsBadArgErr: return SGX_ERROR_INVALID_PARAMETER;
    default: return SGX_ERROR_UNEXPECTED;
    }
}

sgx_status_t sgx_rsa3072_verify(const uint8_t *p_data,
    uint32_t data_size,
    const sgx_rsa3072_public_key_t *p_public,
    const sgx_rsa3072_signature_t *p_signature,
	sgx_rsa_result_t *p_result)
{
    if ((p_data == NULL) || (data_size < 1) || (p_public == NULL) ||
        (p_signature == NULL) || (p_result == NULL))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    *p_result = SGX_RSA_INVALID_SIGNATURE;

    IppStatus ipp_ret = ippStsNoErr;
    IppHashAlgId hash_alg = ippHashAlg_SHA256;

    IppsRSAPublicKeyState* p_rsa_publickey_ctx = NULL;
    Ipp8u *temp_buff = NULL;

    IppsBigNumState* p_pubkey_mod_bn = NULL;
    IppsBigNumState* p_pubkey_exp_bn = NULL;

    int result = 0;

    do
    {
        // Initializa IPP BN from the public key 
        ipp_ret = sgx_ipp_newBN((const Ipp32u *)p_public->mod, sizeof(p_public->mod), &p_pubkey_mod_bn);
        ERROR_BREAK(ipp_ret);

        ipp_ret = sgx_ipp_newBN((const Ipp32u *)&p_public->exp, sizeof(p_public->exp), &p_pubkey_exp_bn);
        ERROR_BREAK(ipp_ret);

        // allocate public key context
        int public_key_ctx_size = 0;

        ipp_ret = ippsRSA_GetSizePublicKey(SGX_RSA3072_KEY_SIZE * 8, SGX_RSA3072_PUB_EXP_SIZE * 8,
            &public_key_ctx_size);
        ERROR_BREAK(ipp_ret);

        p_rsa_publickey_ctx = (IppsRSAPublicKeyState*)malloc(public_key_ctx_size);
        if (!p_rsa_publickey_ctx) {
            ipp_ret = ippStsMemAllocErr;
            break;
        }

        // initialize the public key context
        ipp_ret = ippsRSA_InitPublicKey(SGX_RSA3072_KEY_SIZE * 8, SGX_RSA3072_PUB_EXP_SIZE * 8,
            p_rsa_publickey_ctx, public_key_ctx_size);
        ERROR_BREAK(ipp_ret);

        ipp_ret = ippsRSA_SetPublicKey(p_pubkey_mod_bn, p_pubkey_exp_bn, p_rsa_publickey_ctx);
        ERROR_BREAK(ipp_ret);

        // allocate temp buffer for RSA calculation 
        int public_key_buffer_size = 0;

        ipp_ret = ippsRSA_GetBufferSizePublicKey(&public_key_buffer_size, p_rsa_publickey_ctx);
        ERROR_BREAK(ipp_ret);

        temp_buff = (Ipp8u*)malloc(public_key_buffer_size);
        if (!temp_buff) {
            ipp_ret = ippStsMemAllocErr;
            break;
        }

        // verify the signature 
        ipp_ret = ippsRSAVerify_PKCS1v15(p_data, data_size, *p_signature, &result, p_rsa_publickey_ctx, hash_alg, temp_buff);
    } while (0);

    if ((result != 0) && (ipp_ret == ippStsNoErr))
    {
        /* validation pass successfully */
        *p_result = SGX_RSA_VALID;
    }

    sgx_ipp_secure_free_BN(p_pubkey_mod_bn, sizeof(p_public->mod));
    sgx_ipp_secure_free_BN(p_pubkey_exp_bn, sizeof(p_public->exp));
    SAFE_FREE(p_rsa_publickey_ctx);
    SAFE_FREE(temp_buff);

    switch (ipp_ret)
    {
    case ippStsNoErr: return SGX_SUCCESS;
    case ippStsNoMemErr:
    case ippStsMemAllocErr: return SGX_ERROR_OUT_OF_MEMORY;
    case ippStsNullPtrErr:
    case ippStsLengthErr:
    case ippStsOutOfRangeErr:
    case ippStsSizeErr:
    case ippStsBadArgErr: return SGX_ERROR_INVALID_PARAMETER;
    default: return SGX_ERROR_UNEXPECTED;
    }
}

IppsBigNumState* createBigNumState(int len, const Ipp32u* pData)  {
    int size;
    ippsBigNumGetSize(len, &size);
    IppsBigNumState* pBN = (IppsBigNumState*) ippMalloc(size);;
    ippsBigNumInit(len, pBN);
    if (pData != NULL) {
        ippsSet_BN(IppsBigNumPOS, len, pData, pBN);
    }
    return pBN;
}

extern "C" sgx_status_t sgx_rsa_keygen (int bitsRSA, IppsRSAPublicKeyState **pubkey, IppsRSAPrivateKeyState **privkey) {

    IppStatus status;

    // Security parameter specified for the
    // Miller-Rabin test for probable primality.
    int nTrials = 1;
    // Number of bits of the exponent
    int bitsExp = 24;

    int sizeOfPrimeGen      = -1;
    int sizeOfRandomGen     = -1;
    int sizeOfPublicKey     = -1;
    int sizeOfPrivateKey    = -1;
    int sizeOfScratchBuffer = -1;

    IppsPrimeState * primeGen           = NULL;
    IppsPRNGState * randomGen           = NULL;
    IppsRSAPublicKeyState * publicKey   = NULL;
    IppsRSAPrivateKeyState * privateKey = NULL;
    Ipp8u * scratchBuffer               = NULL;

    Ipp32u E = 65537;
    IppsBigNumState * pSrcPublicExp = createBigNumState (1, &E);
    IppsBigNumState * pModulus      = createBigNumState (bitsRSA / 32, NULL);
    IppsBigNumState * pPublicExp    = createBigNumState (bitsRSA / 32, NULL);
    IppsBigNumState * pPrivateExp   = createBigNumState (bitsRSA / 32, NULL);

    // Prime Number Generator
    ippsPrimeGetSize(bitsRSA, &sizeOfPrimeGen);
    primeGen = (IppsPrimeState *) ippMalloc(sizeOfPrimeGen);
    ippsPrimeInit(bitsRSA, primeGen);

    // Pseudo Random Generator (default settings)
    ippsPRNGGetSize(&sizeOfRandomGen);
    randomGen = (IppsPRNGState*) ippMalloc (sizeOfRandomGen);
    ippsPRNGInit(160, randomGen);

    // Initialize the Public Key State
    ippsRSA_GetSizePublicKey(bitsRSA, bitsExp, &sizeOfPublicKey);
    publicKey = (IppsRSAPublicKeyState *)ippMalloc(sizeOfPublicKey);
    ippsRSA_InitPublicKey(bitsRSA, bitsExp, publicKey, sizeOfPublicKey);

    // Initialize the Private Key State
    int bitsP = (bitsRSA + 1) / 2;
    int bitsQ = bitsRSA - bitsP;
    ippsRSA_GetSizePrivateKeyType2(bitsRSA, bitsRSA, &sizeOfPrivateKey);
    privateKey = (IppsRSAPrivateKeyState *) ippMalloc(sizeOfPrivateKey);
    ippsRSA_InitPrivateKeyType2(bitsP, bitsQ, privateKey, sizeOfPrivateKey);

    // Initialize scratch buffer
    ippsRSA_GetBufferSizePrivateKey(&sizeOfScratchBuffer, privateKey);
    scratchBuffer = (Ipp8u *) ippMalloc (sizeOfScratchBuffer);

    status = ippsRSA_GenerateKeys(
        pSrcPublicExp,
        pModulus, pPublicExp, pPrivateExp,
        privateKey, scratchBuffer, nTrials,
        primeGen, ippsPRNGen, randomGen
    );

    ippsRSA_SetPublicKey(pModulus, pPublicExp, publicKey);

    ippFree(pSrcPublicExp);
    ippFree(pModulus);
    ippFree(pPublicExp);
    ippFree(pPrivateExp);
    ippFree(primeGen);
    ippFree(randomGen);
    // ippFree(publicKey);
    // ippFree(privateKey);
    ippFree(scratchBuffer);

    *pubkey = publicKey;
    *privkey = privateKey;

    if (status == ippStsNoErr)
        return SGX_SUCCESS;
    else
        return SGX_ERROR_INVALID_PARAMETER;
}

//This function will do the rsa oaep encryption with input src[0:src_len] and put the output to buffer dst
//The function will assume that buffer src_len is no more than PVE_RSAOAEP_ENCRYPT_MAXLEN and the buffer size of dst is at least PVE_RSA_KEY_BITS
extern "C" sgx_status_t sgx_rsa_oaep_encrypt(const uint8_t *src, uint32_t src_len, const IppsRSAPublicKeyState *rsa, uint8_t* dst)
{
    const int hashsize = SHA_SIZE_BIT;
    Ipp8u seeds[hashsize];
    IppStatus status = ippStsNoErr;
    sgx_status_t ret = SGX_SUCCESS;
    uint8_t* pub_key_buffer = NULL;
    int pub_key_size;

    ret = sgx_read_rand(seeds, hashsize);
    if(SGX_SUCCESS != ret){
        goto ret_point;
    }

    if((status = ippsRSA_GetBufferSizePublicKey(&pub_key_size, rsa)) != ippStsNoErr)
    {
        ret = SGX_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    //allocate temporary buffer
    pub_key_buffer = (uint8_t*)malloc(pub_key_size);
    if(pub_key_buffer == NULL)
    {
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto ret_point;
    }

    if((status = ippsRSAEncrypt_OAEP(src, src_len,
                                        NULL, 0, seeds,
                                        dst, rsa, IPP_ALG_HASH_SHA256, pub_key_buffer)) != ippStsNoErr)
    {
        ret = (sgx_status_t)status;
        goto ret_point;
    }

ret_point:
    if(pub_key_buffer)
        free(pub_key_buffer);
    return ret;
}

extern "C" sgx_status_t sgx_rsa_oaep_decrypt(const uint8_t *src, int* dst_len, const IppsRSAPrivateKeyState *rsa, uint8_t* dst)
{
    IppStatus status = ippStsNoErr;
    sgx_status_t ret = SGX_SUCCESS;
    uint8_t* priv_key_buffer = NULL;
    int pub_key_size;

    if((status = ippsRSA_GetBufferSizePrivateKey(&pub_key_size, rsa)) != ippStsNoErr)
    {
        ret = SGX_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    //allocate temporary buffer
    priv_key_buffer = (uint8_t*)malloc(pub_key_size);
    if(priv_key_buffer == NULL)
    {
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto ret_point;
    }

    if((status = ippsRSADecrypt_OAEP(src, NULL, 0,
                                        dst, dst_len, rsa, IPP_ALG_HASH_SHA256, priv_key_buffer)) != ippStsNoErr)
    {
        ret = SGX_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

ret_point:
    if(priv_key_buffer)
        free(priv_key_buffer);
    return ret;
}
