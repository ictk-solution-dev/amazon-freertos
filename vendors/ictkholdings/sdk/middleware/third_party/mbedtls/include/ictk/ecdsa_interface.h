#ifndef __ECDSA_INTERFACE_HEADER__
#define __ECDSA_INTERFACE_HEADER__
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include"g3_define.h"

#include "mbedtls/ecdsa.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Compute and write signature
 */

static int puf_pri_key_index = -1;
int ictktls_ecdsa_write_signature( int key, const unsigned char *hash, size_t hlen , unsigned char *sig, size_t *slen);

int ictktls_ecdsa_write_signature_restartable( int key, const unsigned char *hash, size_t hlen, unsigned char *sig, size_t *slen);

int ictktls_ecdsa_read_signature( mbedtls_ecdsa_context *ctx, const unsigned char *hash, size_t hlen, const unsigned char *sig, size_t slen );

int ictktls_ecdsa_read_signature_restartable(mbedtls_ecdsa_context *ctx,int key, const unsigned char *hash, size_t hlen, const unsigned char *sig, size_t slen);

void ictktls_set_puf_priv_index(int key);
int ictktls_get_puf_priv_index();

#ifdef __cplusplus
}
#endif
#endif
