#ifndef __PKPARSE_INTERFACE_HEADER__
#define __PKPARSE_INTERFACE_HEADER__
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include"g3_define.h"
#include "mbedtls/pk.h"
#ifdef __cplusplus
extern "C" {
#endif
int ictktls_pk_parse_key( mbedtls_pk_context *pk,
					  const unsigned char *key, size_t keylen,
					  const unsigned char *pwd, size_t pwdlen );

#ifdef __cplusplus
}
#endif
#endif
