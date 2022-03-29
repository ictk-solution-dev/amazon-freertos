#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#ifdef ICTK_TLS
#include "g3_api.h"
#endif

#include "mbedtls/pk.h"
#include "ictk/pkparse_interface.h"


#ifdef __cplusplus
extern "C" {
#endif
/*
 * Parse a private key
 */
int ictktls_pk_parse_key( mbedtls_pk_context *pk,
				  const unsigned char *key, size_t keylen,
				  const unsigned char *pwd, size_t pwdlen )

{
	int ret = 0;
	const mbedtls_pk_info_t *pk_info;
#ifdef ICTK_TLS
#if 0
#if defined(MBEDTLS_RSA_C)
                mbedtls_pk_init( pk );
		pk_info = mbedtls_pk_info_from_type( MBEDTLS_PK_RSA );
		if( mbedtls_pk_setup( pk, pk_info ) == 0 &&
			pk_parse_key_pkcs1_der( mbedtls_pk_rsa( *pk ), key, keylen ) == 0 )
		{
			return( 0 );
		}
	
		mbedtls_pk_free( pk );
#endif /* MBEDTLS_RSA_C */
#endif	
#if defined(MBEDTLS_ECP_C)
		pk_info = mbedtls_pk_info_from_type( MBEDTLS_PK_ECKEY );
                mbedtls_pk_init( pk );
		if( mbedtls_pk_setup( pk, pk_info ) == 0)
		{
			return( 0 );
		}
		mbedtls_pk_free( pk );
#endif /* MBEDTLS_ECP_C */
#endif
	return ret;
}

#ifdef __cplusplus
}
#endif

