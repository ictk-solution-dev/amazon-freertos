#ifndef __SSL_TLS_INTERFACE_HEADER__
#define __SSL_TLS_INTERFACE_HEADER__
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include"g3_define.h"
#include "mbedtls/ssl.h"
#ifdef __cplusplus
extern "C" {
#endif

int ictktls_x509_crt_parse_der(const unsigned char *buf,		size_t buflen);

int ictktls_ecdh(int en_ecdh_mode, const unsigned char* pub, int pub_len, const unsigned char* ecdh_random, unsigned char *Qp, unsigned char* ecdh_value, int *ecdh_value_len);

int ictktls_mac_encrypt(const unsigned char* tls_header_without_size,  const unsigned char* client_iv, const unsigned char* header_random, const unsigned char *msg, int msg_len, unsigned char* crypto , int* cryto_len);

int ictktls_decrypt_verify(const unsigned char* tls_header_without_size,  const unsigned char* server_iv, const unsigned char* header_random, const unsigned char* crypto , int cryto_len, unsigned char *msg, int* msg_len);

int ictktls_ssl_derive_keys( mbedtls_ssl_context *ssl );

int ictk_ssl_encrypt_buf( mbedtls_ssl_context *ssl );

int ictk_ssl_decrypt_buf( mbedtls_ssl_context *ssl );

#ifdef __cplusplus
}
#endif
#endif
