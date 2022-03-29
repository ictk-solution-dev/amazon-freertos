#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "ictk/x509write_csr_interface.h"

/*
 * EC public key is an EC point
 */
static int ictk_pk_write_ec_pubkey( unsigned char **p, unsigned char *start,
                               mbedtls_ecp_keypair *ec )
{
    int ret;
    size_t len = 0;
    unsigned char buf[MBEDTLS_ECP_MAX_PT_LEN];
	uint8_t tx_buffer[256] = {0,};
	uint8_t rx_buffer[256] = {0,};	
	uint32_t size = 0;
    uint16_t rx_buffer_size = sizeof(rx_buffer);
	memset(tx_buffer, 0x00, sizeof(tx_buffer));
	memset(rx_buffer, 0x00, sizeof(rx_buffer));
	rx_buffer_size = sizeof(rx_buffer);
	
	size = set_buffer_from_hexstr(tx_buffer,"8C720001");

	ret = G3_Cmd_BUFFER(tx_buffer,size,rx_buffer,&rx_buffer_size);
	buf[0] = 0x04;
	len = 65;
	memcpy(&buf[1], rx_buffer, rx_buffer_size);
	
	printf("ictk_pk_write_ec_pubkey public key len[%d]\n",rx_buffer_size);
	for(int k = 0 ; k < rx_buffer_size ; k++){
	printf("%02X",buf[k]);
	}
	printf("\n"); 
    //if( ( ret = mbedtls_ecp_point_write_binary( &ec->grp, &ec->Q,
    //                                    MBEDTLS_ECP_PF_UNCOMPRESSED,
    //                                    &len, buf, sizeof( buf ) ) ) != 0 )
    //{
    //    return( ret );
    //}

    if( *p < start || (size_t)( *p - start ) < len )
        return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

    *p -= len;
    memcpy( *p, buf, len );

    return( (int) len );
}

int ictktls_pk_write_pubkey( unsigned char **p, unsigned char *start,
                             const mbedtls_pk_context *key )
{
    int ret;
    size_t len = 0;

    if( mbedtls_pk_get_type( key ) == MBEDTLS_PK_ECKEY )
        MBEDTLS_ASN1_CHK_ADD( len, ictk_pk_write_ec_pubkey( p, start, mbedtls_pk_ec( *key ) ) );
    else
        return( MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE );

    return( (int) len );
}

/*
 * ECParameters ::= CHOICE {
 *   namedCurve         OBJECT IDENTIFIER
 * }
 */
static int ictk_pk_write_ec_param( unsigned char **p, unsigned char *start,
                              mbedtls_ecp_keypair *ec )
{
    int ret;
    size_t len = 0;
    const char *oid;
    size_t oid_len;
	printf("ictk_pk_write_ec_param group id[%d]\n",ec->grp.id);
    if( ( ret = mbedtls_oid_get_oid_by_ec_grp( MBEDTLS_ECP_DP_SECP256R1/*ec->grp.id*/, &oid, &oid_len ) ) != 0 )
        return( ret );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_oid( p, start, oid, oid_len ) );

    return( (int) len );
}


int ictktls_pk_write_pubkey_der( mbedtls_pk_context *key, unsigned char *buf, size_t size )
{
    int ret;
    unsigned char *c;
    size_t len = 0, par_len = 0, oid_len;
    const char *oid;

    if( size == 0 )
        return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

    c = buf + size;

    MBEDTLS_ASN1_CHK_ADD( len, ictktls_pk_write_pubkey( &c, buf, key ) );

    if( c - buf < 1 )
        return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

    /*
     *  SubjectPublicKeyInfo  ::=  SEQUENCE  {
     *       algorithm            AlgorithmIdentifier,
     *       subjectPublicKey     BIT STRING }
     */
    *--c = 0;
    len += 1;

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, buf, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, buf, MBEDTLS_ASN1_BIT_STRING ) );

    if( ( ret = mbedtls_oid_get_oid_by_pk_alg( mbedtls_pk_get_type( key ),
                                       &oid, &oid_len ) ) != 0 )
    {
        return( ret );
    }

#if defined(MBEDTLS_ECP_C)
    if( mbedtls_pk_get_type( key ) == MBEDTLS_PK_ECKEY )
    {
        MBEDTLS_ASN1_CHK_ADD( par_len, ictk_pk_write_ec_param( &c, buf, mbedtls_pk_ec( *key ) ) );
    }
#endif

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_algorithm_identifier( &c, buf, oid, oid_len,
                                                        par_len ) );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, buf, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                MBEDTLS_ASN1_SEQUENCE ) );

    return( (int) len );
}


