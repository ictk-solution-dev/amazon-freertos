/*
 *  Minimal configuration for TLS 1.1 (RFC 4346)
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
/*
 * Minimal configuration for TLS 1.1 (RFC 4346), implementing only the
 * required ciphersuite: MBEDTLS_TLS_RSA_WITH_3DES_EDE_CBC_SHA
 *
 * See README.txt for usage instructions.
 */

#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H	//Deleted by ICTK

/* System support */
#define MBEDTLS_HAVE_ASM
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_CALLOC_MACRO pvPortCalloc //mbedtls_calloc //
#define MBEDTLS_PLATFORM_FREE_MACRO	vPortFree //mbedtls_free //



/* mbed TLS feature support */
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
#define MBEDTLS_SSL_PROTO_SSL3
#define MBEDTLS_SSL_PROTO_TLS1
#define MBEDTLS_SSL_PROTO_TLS1_1
#define MBEDTLS_SSL_PROTO_TLS1_2
//#define MBEDTLS_THREADING_C
#define MBEDTLS_PLATFORM_C

/* mbed TLS modules */
#define MBEDTLS_ARIA_C
#define MBEDTLS_CAMELLIA_C
#define MBEDTLS_CHACHAPOLY_C
#define MBEDTLS_POLY1305_C
#define MBEDTLS_CHACHA20_C
#define MBEDTLS_AES_C
#define MBEDTLS_ARC4_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_DES_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_MD_C
#define MBEDTLS_MD5_C
#define MBEDTLS_NET_C
#define MBEDTLS_OID_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_RSA_C
#define MBEDTLS_SHA1_C
#define MBEDTLS_SHA256_C

#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_X509_USE_C
#define MBEDTLS_SSL_SERVER_NAME_INDICATION
#define MBEDTLS_SSL_ALPN
#define MBEDTLS_KEY_EXCHANGE_PSK_ENABLED
#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_ENTROPY_HARDWARE_ALT
#define MBEDTLS_SSL_ENCRYPT_THEN_MAC //added by ICTK

// add for iCloud feature
#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECDH_C
#define MBEDTLS_PK_WRITE_C
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#define MBEDTLS_GCM_C
#define MBEDTLS_CCM_C	//added by ICTK
#define MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
#define MBEDTLS_ECP_DP_SECP192R1_ENABLED
#define MBEDTLS_ECP_DP_SECP224R1_ENABLED
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED
#define MBEDTLS_ECP_DP_SECP521R1_ENABLED
#define MBEDTLS_ECP_DP_SECP192K1_ENABLED
#define MBEDTLS_ECP_DP_SECP224K1_ENABLED
#define MBEDTLS_ECP_DP_SECP256K1_ENABLED
#define MBEDTLS_ECP_DP_BP256R1_ENABLED
#define MBEDTLS_ECP_DP_BP384R1_ENABLED
#define MBEDTLS_ECP_DP_BP512R1_ENABLED
#define MBEDTLS_ECP_DP_CURVE25519_ENABLED
#define EXTEND_BUF_WITH_TERMINATE 

// end

//add for ZTP
#define MBEDTLS_X509_CREATE_C 		
#define MBEDTLS_PEM_WRITE_C
#define MBEDTLS_X509_CSR_PARSE_C
#define MBEDTLS_X509_CSR_WRITE_C 
#define MBEDTLS_X509_CRT_WRITE_C


//end
 
/* For test certificates */
#define MBEDTLS_BASE64_C
#define MBEDTLS_CERTS_C
#define MBEDTLS_PEM_PARSE_C

#ifdef CONFIG_MBEDTLS_HW_CRYPTO
#define MBEDTLS_AES_ALT
#define MBEDTLS_DES_ALT
#define MBEDTLS_MD5_ALT
#define MBEDTLS_SHA1_ALT
#define MBEDTLS_SHA256_ALT
#define MBEDTLS_SHA512_ALT
#endif

#define MBEDTLS_SSL_MAX_CONTENT_LEN         (6*1024)   /**< Size of the input / output buffer */

#define MBEDTLS_AES_ROM_TABLES

#define MBEDTLS_GCM_C
#define MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED

#define MBEDTLS_ECP_NIST_OPTIM

#ifndef MTK_DEBUG_LEVEL_NONE
#define MBEDTLS_DEBUG_C
#endif

#define MBEDTLS_SELF_TEST

/* MTK revisions */
#define MBEDTLS_MTK
//#define MBEDTLS_THREADING_FREERTOS
//#define MBEDTLS_THREADING_PTHREAD

#include "mbedtls/check_config.h"

#if 1
#define MBEDTLS_CTR_DRBG_USE_128_BIT_KEY              /*added by ICTK*//**< Use 128-bit key for CTR_DRBG - may reduce security (see ctr_drbg.h) */



//#define MBEDTLS_AES_ALT
//#define MEDIATEK_AES_ENGINE


/**
 * \def ICTK_TLS_PREMASTER_IN_PUF
 *
 * generate premaster key in puf
 *
 * 
 */

#define MBEDTLS_SSL_CIPHERSUITES        MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256//MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256//MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256

//#define ICTK_TLS_GEN_R_IN_PUF
#define ICTK_TLS_CHECK_CN_NAME

#define ICTKTLS_AES_USAGE_RNG			    111//1
#define ICTKTLS_AES_USAGE_ENC_DATA		112//2
#define ICTKTLS_AES_USAGE_DEC_DATA		113//3


#define USE_ECB							          0

#define ICTK_PUF_DATA_UNIT_LEN			  32

#if 1 /// AWS ROOT CA
#define ECC_CERT_TOTAL_LEN				    448
#define ECC_CERT_UNIT_LEN				      14
#else /// ICTK ROOT CA
#define ECC_CERT_TOTAL_LEN				    384	/// 448 ?
#define ECC_CERT_UNIT_LEN				      12
#endif


#define CLIENT_SIGN_KEYINDEX			    114//4
#define CLIENT_VERIFICATION_KEYINDEX	115//8
#endif

#endif /* MBEDTLS_CONFIG_H */

