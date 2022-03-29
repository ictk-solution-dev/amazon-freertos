#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif
#ifdef ICTK_TLS
#include "g3_api.h"
#endif

#include "ictk/ecdsa_interface.h"

#include "mbedtls/bignum.h"
#include "mbedtls/ecp.h"
#include "mbedtls/asn1.h"
#include "mbedtls/pk.h"

#ifdef G3_PKCS11
#include "g3_pkcs11.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef ICTK_TLS
extern int ecdsa_signature_to_asn1( const mbedtls_mpi *r, const mbedtls_mpi *s,unsigned char *sig, size_t *slen );
#endif

int ictktls_ecdsa_write_signature( int key, const unsigned char *hash, size_t hlen , unsigned char *sig, size_t *slen)
{
    key = ictktls_get_puf_priv_index();
    return( ictktls_ecdsa_write_signature_restartable(key, hash, hlen, sig, slen) );
}

int ictktls_ecdsa_write_signature_restartable( int key, const unsigned char *hash, size_t hlen, unsigned char *sig, size_t *slen){
	int ret = 0;
#ifdef ICTK_TLS                           
	mbedtls_mpi r, s;
	unsigned char r_buf[32];
	unsigned char s_buf[32];
	ST_SIGN_ECDSA sign;

	mbedtls_mpi_init( &r );
	mbedtls_mpi_init( &s );
	
	ret = g3api_sign(key, SIGN_ECDSA_EXT_SHA256, hash, hlen, &sign, sizeof(ST_SIGN_ECDSA));
	if(ret == 0){
		memcpy(r_buf,&(sign.r[0]),32);
		memcpy(s_buf,&(sign.s[0]),32);
	}
	if(ret == 0){
		//printf("ecdsa sign : success\r\n");
		mbedtls_mpi_read_binary(&r,r_buf,sizeof(r_buf));
		mbedtls_mpi_read_binary(&s,s_buf,sizeof(s_buf));
	}
	else
		;//printf("ecdsa sign : failure\r\n");
	
	MBEDTLS_MPI_CHK( ecdsa_signature_to_asn1( &r, &s, sig, slen ) );

cleanup:
	mbedtls_mpi_free( &r );
	mbedtls_mpi_free( &s );
#endif
	return( ret );

}

int ictktls_ecdsa_read_signature( mbedtls_ecdsa_context *ctx,
                          const unsigned char *hash, size_t hlen,
                          const unsigned char *sig, size_t slen )
{
    int key = ictktls_get_puf_priv_index() + 1;
    int ret = ictktls_ecdsa_read_signature_restartable(ctx, key, hash, hlen, sig, slen );
#ifdef G3_PKCS11    
    ictktls_set_puf_priv_index(G3_PKCS11_PRV_KEY_SECTOR);
#endif
    return ret;
    //return( ictktls_ecdsa_read_signature_restartable(
    //            ctx, key, hash, hlen, sig, slen ) );
}

int ictktls_ecdsa_read_signature_restartable(mbedtls_ecdsa_context *ctx,int key, const unsigned char *hash, size_t hlen, const unsigned char *sig, size_t slen){
	int ret = 0;
#ifdef ICTK_TLS
	unsigned char *p = (unsigned char *) sig;
    const unsigned char *end = sig + slen;
    size_t len;
    mbedtls_mpi r, s;
	unsigned char r_buf[32];
	unsigned char s_buf[32];
	unsigned char pub1_buf[32]= {0,};
	unsigned char pub2_buf[32]= {0,};
	mbedtls_ecp_point *Q ;
	ST_SIGN_ECDSA sign;

    mbedtls_mpi_init( &r );
    mbedtls_mpi_init( &s );

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        ret += MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    if( p + len != end )
    {
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA +
              MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
        goto cleanup;
    }

    if( ( ret = mbedtls_asn1_get_mpi( &p, end, &r ) ) != 0 ||
        ( ret = mbedtls_asn1_get_mpi( &p, end, &s ) ) != 0 )
    {
        ret += MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

	Q = &ctx->Q;
	mbedtls_mpi_write_binary(&r,r_buf,32);
	mbedtls_mpi_write_binary(&s,s_buf,32);
	mbedtls_mpi_write_binary(&Q->X,pub1_buf,32);
	mbedtls_mpi_write_binary(&Q->Y,pub2_buf,32);
     
        
#ifdef G3_PKCS11
        if(key == G3_PKCS11_PUB_KEY_SECTOR)
        {
          key = CLIENT_VERIFICATION_KEYINDEX;
        }
        else
        {
            ret = g3api_write_key_value(key, KEY_AREA, PLAIN_TEXT, &pub1_buf[0], 32); //It must be changed that anyone cann't know the key index is saved...
            ret = g3api_write_key_value(key+1, KEY_AREA, PLAIN_TEXT, &pub2_buf[0], 32);
        }
#else
        ret = g3api_write_key_value(key, KEY_AREA, PLAIN_TEXT, &pub1_buf[0], 32); //It must be changed that anyone cann't know the key index is saved...
        ret = g3api_write_key_value(key+1, KEY_AREA, PLAIN_TEXT, &pub2_buf[0], 32);
#endif
        
	memcpy(&(sign.r[0]),&r_buf[0] ,32);
	memcpy(&(sign.s[0]),&s_buf[0] ,32);
	ret = g3api_verify(key, VERIFY_ECDSA_EXT_SHA256, hash, hlen, &sign, sizeof(ST_SIGN_ECDSA));
/*
	if(ret != 0){
		printf("[ICTK]verification : failure\r\n");
	}else{
		printf("[ICTK]verification : success\r\n");
	}
*/
cleanup:
    mbedtls_mpi_free( &r );
    mbedtls_mpi_free( &s );	
#endif
	return ret;
}

void ictktls_set_puf_priv_index(int key){
	puf_pri_key_index = key;
}
int ictktls_get_puf_priv_index(){
	return puf_pri_key_index;
}

#ifdef __cplusplus
}
#endif
