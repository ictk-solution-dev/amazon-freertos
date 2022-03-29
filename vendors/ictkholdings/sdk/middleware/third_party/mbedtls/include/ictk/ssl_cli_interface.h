#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif
#include <string.h>
#ifdef __cplusplus
extern "C" {
#endif
  
int ictktls_ecdh_calc_secret(int ecdh_mode, unsigned char *pub, unsigned char *buf, size_t *olen, const unsigned char* ecdh_random, unsigned char* ecdh_value, size_t *ecdh_value_len);

#ifdef __cplusplus
}
#endif

