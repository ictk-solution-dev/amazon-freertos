
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif
#include "mbedtls/debug.h"
#include "mbedtls/ssl_internal.h"

#ifdef ICTK_TLS
#include "g3_api.h"
#endif

#include "ictk/ssl_tls_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef ICTK_TLS
extern int tls_prf_sha256( const unsigned char *secret, size_t slen, const char *label, const unsigned char *random, size_t rlen, unsigned char *dstbuf, size_t dlen );
extern void ssl_calc_verify_tls_sha256( mbedtls_ssl_context *,unsigned char * );
extern void ssl_calc_finished_tls_sha256(         mbedtls_ssl_context *ssl, unsigned char *buf, int from );
#endif

/* Length of the "epoch" field in the record header */
static inline size_t ssl_ep_len( const mbedtls_ssl_context *ssl )
{
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
        return( 2 );
#else
    ((void) ssl);
#endif
    return( 0 );
}

int ictktls_x509_crt_parse_der(const unsigned char *buf,        size_t buflen){
	int ret = 0 ;
#ifdef ICTK_TLS
	ST_KEY_VALUE recv_key;
	unsigned int k = buflen/32;
	int checkindex = buflen%32;	
	if(checkindex != 0) k++;
	int startPos = 0;
	unsigned char cacert[32] ={0x30, 0x82, 0x01, 0x62, 0x30, 0x82, 0x01, 0x07, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30, 0x31, 0x31, 0x0B};

    if(memcmp(cacert , &buf[0] , ICTK_PUF_DATA_UNIT_LEN) == 0){
		startPos = ECC_CERT_UNIT_LEN;		
    }else{
    	startPos = 2*ECC_CERT_UNIT_LEN;		
    }
	for(int j = 0 ; j < k ; j++){			
		ret = g3api_write_key_value(j + startPos , DATA_AREA_0, PLAIN_TEXT, buf + ( j*ICTK_PUF_DATA_UNIT_LEN), ICTK_PUF_DATA_UNIT_LEN);
	}
#endif	
	return ret;
}

int ictktls_ecdh(int en_ecdh_mode, const unsigned char* pub, int pub_len, const unsigned char* ecdh_random, unsigned char *Qp, unsigned char* ecdh_value, int *ecdh_value_len){
	int ret  = 0;
#ifdef ICTK_TLS
	ST_ECC_PUBLIC Q_chip ={0,};
	ST_ECDH_KEY_BLOCK st_ecdh_key_block = {0,};
	ST_ECDH_RANDOM st_ecdh_random ={0,};
	ST_ECC_PUBLIC Qb;
	ST_ECDH_IV ecdh_iv;

	//printf("[ICTK]ictktls_ecdh_calc_secret\r\n");

	//printf("[ICTK]pre secret\r\n");

	memcpy(Qb.puk , pub , pub_len );
	memcpy(&st_ecdh_random.client[0], &ecdh_random[0], 32);
	memcpy(&st_ecdh_random.server[0], &ecdh_random[32], 32);

	if(en_ecdh_mode == 0x0011){

		ret = g3api_ecdh(GEN_TLS_BLOCK , &Qb, sizeof(Qb), &st_ecdh_random , &Q_chip , &st_ecdh_key_block , sizeof(ST_ECDH_KEY_BLOCK));
		printf("ictktls_ecdh[GEN_TLS_BLOCK] is called\r\n");
		
		for(int i = 0 ; i < 32 ; i++){
			printf("%02X ",st_ecdh_key_block.client_mac_key[i]);
		}
		
		printf("\r\n");
		
		memcpy( &ecdh_value[0], st_ecdh_key_block.client_mac_key, 32);	
		memcpy( &ecdh_value[32], st_ecdh_key_block.server_mac_key, 32);
		memcpy( &ecdh_value[64], st_ecdh_key_block.client_key, 16);
		memcpy( &ecdh_value[80], st_ecdh_key_block.server_key, 16);
		memcpy( &ecdh_value[96], st_ecdh_key_block.client_iv, 16);
		memcpy( &ecdh_value[112], st_ecdh_key_block.server_iv, 16);
		*ecdh_value_len = 128 ;
	}else if(en_ecdh_mode == 0x0012){
		ret = g3api_ecdh(SET_TLS_SESSION_KEY , &Qb, sizeof(Qb), &st_ecdh_random , &Q_chip , &ecdh_iv, sizeof(ecdh_iv));
		memcpy( &ecdh_value[0], ecdh_iv.client_iv, 16);		
		memcpy( &ecdh_value[16], ecdh_iv.server_iv, 16); 
		*ecdh_value_len = 32 ;	
		printf("ictktls_ecdh[SET_TLS_SESSION_KEY] is called\r\n");
	}
	memcpy(Qp, &Q_chip.puk[0], 64);
#endif
	return ret;
}

int ictktls_mac_encrypt(const unsigned char* tls_header_without_size,  const unsigned char* client_iv, const unsigned char* header_random, const unsigned char *msg, int msg_len, unsigned char* crypto , int* cryto_len){
	int ret  = 0;
#ifdef ICTK_TLS
	ST_TLS_INTER_HEADER_WITHOUT_SIZE st_tls_inter_header_without_size;	
	ST_IV client_iv_ = {0,};
	ST_ECDH_IV st_ecdh_iv = { 0, };
	const unsigned char inner_header[11] = { 0, };// = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0x03, 0x03};
	ST_DATA_16 head_rand = {0,};
	memcpy(client_iv_.iv , client_iv , 16);	
	memcpy(head_rand.data , header_random , 16);
	
	ret = g3api_tls_mac_encrypt((ST_TLS_INTER_HEADER_WITHOUT_SIZE*)tls_header_without_size , &client_iv_, &head_rand , msg , msg_len , crypto , cryto_len);
#endif
	return ret;
}
int ictktls_decrypt_verify(const unsigned char* tls_header_without_size, const unsigned char* server_iv, const unsigned char* header_random, const unsigned char* crypto, int cryto_len, unsigned char *msg_, int* msg_len_) {
	int ret = 0;
#ifdef ICTK_TLS
	ST_ECDH_IV st_ecdh_iv = { 0, };
	ST_TLS_INTER_HEADER_WITHOUT_SIZE st_tls_inter_header_without_size;
	ST_IV server_iv_ = { 0, };
	const unsigned char inner_header[11] = { 0, };//{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0x03, 0x03};
	ST_DATA_16 head_rand = { 0, };
	unsigned char outbuff2[1024] = { 0, };
	int out_size2 = 1024;
	unsigned char input[1024];

	memcpy(&server_iv_.iv, server_iv, 16);
	memcpy((void*)&inner_header[0] , tls_header_without_size , 11);
	memcpy(&input[0], crypto, cryto_len);

	ret = g3api_tls_decrypt_verify((ST_TLS_INTER_HEADER_WITHOUT_SIZE*)tls_header_without_size, &server_iv_,
		crypto,
		cryto_len,
		&head_rand, outbuff2, &out_size2);
	memcpy(msg_, outbuff2 ,out_size2);
	*msg_len_ = out_size2;	
#endif
	return ret;
}

int ictktls_ssl_derive_keys( mbedtls_ssl_context *ssl )
{
    int ret = 0;
#ifdef ICTK_TLS
    unsigned char tmp[64];
	unsigned char keyblk[128];

    unsigned char *key1;
    unsigned char *key2;
    unsigned char *mac_enc;
    unsigned char *mac_dec;
    size_t mac_key_len;
    size_t iv_copy_len;
    const mbedtls_cipher_info_t *cipher_info;
    const mbedtls_md_info_t *md_info;
	unsigned char puk[64];
	unsigned char Qp[64];
	unsigned char ecdh_value[128];


    mbedtls_ssl_session *session = ssl->session_negotiate;
    mbedtls_ssl_transform *transform = ssl->transform_negotiate;
    mbedtls_ssl_handshake_params *handshake = ssl->handshake;
	memcpy(keyblk, ssl->handshake->keyblk, sizeof(ssl->handshake->keyblk));

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=>[ICTK] derive keys" ) );

    cipher_info = mbedtls_cipher_info_from_type( transform->ciphersuite_info->cipher );
    if( cipher_info == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "cipher info for %d not found",
                            transform->ciphersuite_info->cipher ) );
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    md_info = mbedtls_md_info_from_type( transform->ciphersuite_info->mac );
    if( md_info == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "mbedtls_md info for %d not found",
                            transform->ciphersuite_info->mac ) );
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }
#if defined(MBEDTLS_SHA256_C)
    if( ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_3 )
    {
    	MBEDTLS_SSL_DEBUG_MSG( 1, ( "[ICTK]tls_prf_sha256" ) );
        handshake->tls_prf = tls_prf_sha256;
        handshake->calc_verify = ssl_calc_verify_tls_sha256;
        handshake->calc_finished = ssl_calc_finished_tls_sha256;
    }
    else
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    mbedtls_platform_zeroize( handshake->randbytes,
                              sizeof( handshake->randbytes ) );


							  /*
     * Determine the appropriate key, IV and MAC length.
     */

    transform->keylen = cipher_info->key_bitlen / 8;

    if( cipher_info->mode == MBEDTLS_MODE_GCM ||
        cipher_info->mode == MBEDTLS_MODE_CCM ||
        cipher_info->mode == MBEDTLS_MODE_CHACHAPOLY )
    {
        size_t taglen, explicit_ivlen;

        transform->maclen = 0;
        mac_key_len = 0;

        /* All modes haves 96-bit IVs;
         * GCM and CCM has 4 implicit and 8 explicit bytes
         * ChachaPoly has all 12 bytes implicit
         */
        transform->ivlen = 12;
        if( cipher_info->mode == MBEDTLS_MODE_CHACHAPOLY )
            transform->fixed_ivlen = 12;
        else
            transform->fixed_ivlen = 4;

        /* All modes have 128-bit tags, except CCM_8 (ciphersuite flag) */
        taglen = transform->ciphersuite_info->flags &
                  MBEDTLS_CIPHERSUITE_SHORT_TAG ? 8 : 16;


        /* Minimum length of encrypted record */
        explicit_ivlen = transform->ivlen - transform->fixed_ivlen;
        transform->minlen = explicit_ivlen + taglen;
    }
    else
    {
        /* Initialize HMAC contexts */
        if( ( ret = mbedtls_md_setup( &transform->md_ctx_enc, md_info, 1 ) ) != 0 ||
            ( ret = mbedtls_md_setup( &transform->md_ctx_dec, md_info, 1 ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_md_setup", ret );
            return( ret );
        }

        /* Get MAC length */
        mac_key_len = mbedtls_md_get_size( md_info );
        transform->maclen = mac_key_len;

#if defined(MBEDTLS_SSL_TRUNCATED_HMAC)
        /*
         * If HMAC is to be truncated, we shall keep the leftmost bytes,
         * (rfc 6066 page 13 or rfc 2104 section 4),
         * so we only need to adjust the length here.
         */
        if( session->trunc_hmac == MBEDTLS_SSL_TRUNC_HMAC_ENABLED )
        {
            transform->maclen = MBEDTLS_SSL_TRUNCATED_HMAC_LEN;

#if defined(MBEDTLS_SSL_TRUNCATED_HMAC_COMPAT)
            /* Fall back to old, non-compliant version of the truncated
             * HMAC implementation which also truncates the key
             * (Mbed TLS versions from 1.3 to 2.6.0) */
            mac_key_len = transform->maclen;
#endif
        }
#endif /* MBEDTLS_SSL_TRUNCATED_HMAC */

        /* IV length */
        transform->ivlen = cipher_info->iv_size;

        /* Minimum length */
        if( cipher_info->mode == MBEDTLS_MODE_STREAM )
            transform->minlen = transform->maclen;
        else
        {
            /*
             * GenericBlockCipher:
             * 1. if EtM is in use: one block plus MAC
             *    otherwise: * first multiple of blocklen greater than maclen
             * 2. IV except for SSL3 and TLS 1.0
             */
#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
            if( session->encrypt_then_mac == MBEDTLS_SSL_ETM_ENABLED )
            {
                transform->minlen = transform->maclen
                                  + cipher_info->block_size;
            }
            else
#endif
            {
                transform->minlen = transform->maclen
                                  + cipher_info->block_size
                                  - transform->maclen % cipher_info->block_size;
            }

#if defined(MBEDTLS_SSL_PROTO_SSL3) || defined(MBEDTLS_SSL_PROTO_TLS1)
            if( ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_0 ||
                ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_1 )
                ; /* No need to adjust minlen */
            else
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1_1) || defined(MBEDTLS_SSL_PROTO_TLS1_2)
            if( ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_2 ||
                ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_3 )
            {
                transform->minlen += transform->ivlen;
            }
            else
#endif
            {
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
                return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
            }
        }
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "keylen: %d, minlen: %d, ivlen: %d, maclen: %d",
                   transform->keylen, transform->minlen, transform->ivlen,
                   transform->maclen ) );

    /*
     * Finally setup the cipher contexts, IVs and MAC secrets.
     */

#if defined(MBEDTLS_SSL_CLI_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
    {
        key1 = keyblk + mac_key_len * 2; /*client key*/
        key2 = keyblk + mac_key_len * 2 + transform->keylen;/*server key*/

        mac_enc = keyblk;	/*client mac key*/
        mac_dec = keyblk + mac_key_len; /*server mac key*/

        /*
         * This is not used in TLS v1.1.
         */
        iv_copy_len = ( transform->fixed_ivlen ) ?
                            transform->fixed_ivlen : transform->ivlen;
        memcpy( transform->iv_enc, key2 + transform->keylen,  iv_copy_len );/*client iv*/
        memcpy( transform->iv_dec, key2 + transform->keylen + iv_copy_len,
                iv_copy_len );		/*server iv*/
    }
    else
#endif /* MBEDTLS_SSL_CLI_C */
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

#if defined(MBEDTLS_SSL_PROTO_TLS1) || defined(MBEDTLS_SSL_PROTO_TLS1_1) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_2)
    if( ssl->minor_ver >= MBEDTLS_SSL_MINOR_VERSION_1 )
    {
        /* For HMAC-based ciphersuites, initialize the HMAC transforms.
           For AEAD-based ciphersuites, there is nothing to do here. */
           
        if( mac_key_len != 0 )
        {
        	MBEDTLS_SSL_DEBUG_MSG( 1, ( "[ICTK]mbedtls_md_hmac_starts ==> mac enc/dec" ) );
            mbedtls_md_hmac_starts( &transform->md_ctx_enc, mac_enc, mac_key_len );//mac_enc -> client
            mbedtls_md_hmac_starts( &transform->md_ctx_dec, mac_dec, mac_key_len );//mac_dec -> server
        }
    }
    else
#endif
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    if( ( ret = mbedtls_cipher_setup( &transform->cipher_ctx_enc,
                                 cipher_info ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_setup", ret );
        return( ret );
    }

    if( ( ret = mbedtls_cipher_setup( &transform->cipher_ctx_dec,
                                 cipher_info ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_setup", ret );
        return( ret );
    }

    if( ( ret = mbedtls_cipher_setkey( &transform->cipher_ctx_enc, key1,
                               cipher_info->key_bitlen,
                               MBEDTLS_ENCRYPT ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_setkey", ret );
        return( ret );
    }

    if( ( ret = mbedtls_cipher_setkey( &transform->cipher_ctx_dec, key2,
                               cipher_info->key_bitlen,
                               MBEDTLS_DECRYPT ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_setkey", ret );
        return( ret );
    }

#if defined(MBEDTLS_CIPHER_MODE_CBC)
    if( cipher_info->mode == MBEDTLS_MODE_CBC )
    {
        if( ( ret = mbedtls_cipher_set_padding_mode( &transform->cipher_ctx_enc,
                                             MBEDTLS_PADDING_NONE ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_set_padding_mode", ret );
            return( ret );
        }

        if( ( ret = mbedtls_cipher_set_padding_mode( &transform->cipher_ctx_dec,
                                             MBEDTLS_PADDING_NONE ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_set_padding_mode", ret );
            return( ret );
        }
    }
#endif /* MBEDTLS_CIPHER_MODE_CBC */

    mbedtls_platform_zeroize( keyblk, sizeof( keyblk ) );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= [ICTK]derive keys" ) );
#endif
    return( 0 );
}

int ictk_ssl_encrypt_buf( mbedtls_ssl_context *ssl ){
#ifdef ICTK_TLS
	mbedtls_cipher_mode_t mode;
	int auth_done = 0;
	unsigned char tmp_pseudo_hdr[13];
	unsigned char crypto[1024];
	unsigned char plain[16];
	int crypto_len = 1024;	
	unsigned char random[16]= {0,};
	unsigned char tmp_mac[MBEDTLS_SSL_MAC_ADD];

	MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> [ICTK]encrypt buf" ) );

	if( ssl->session_out == NULL || ssl->transform_out == NULL )
	{
		MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
		return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
	}

	mode = mbedtls_cipher_get_cipher_mode( &ssl->transform_out->cipher_ctx_enc );

	MBEDTLS_SSL_DEBUG_BUF( 4, "before encrypt: output payload",
					  ssl->out_msg, ssl->out_msglen ); //hupark command(4byte) + data(12byte)
#if defined(MBEDTLS_ARC4_C) || defined(MBEDTLS_CIPHER_NULL_CIPHER)
			if( mode == MBEDTLS_MODE_STREAM )
			{
				int ret;
				size_t olen = 0;
		
				MBEDTLS_SSL_DEBUG_MSG( 3, ( "before encrypt: msglen = %d, "
									"including %d bytes of padding",
							   ssl->out_msglen, 0 ) );
		
				if( ( ret = mbedtls_cipher_crypt( &ssl->transform_out->cipher_ctx_enc,
										   ssl->transform_out->iv_enc,
										   ssl->transform_out->ivlen,
										   ssl->out_msg, ssl->out_msglen,
										   ssl->out_msg, &olen ) ) != 0 )
				{
					MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_crypt", ret );
					return( ret );
				}
		
				if( ssl->out_msglen != olen )
				{
					MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
					return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
				}
			}
			else
#endif /* MBEDTLS_ARC4_C || MBEDTLS_CIPHER_NULL_CIPHER */
#if defined(MBEDTLS_GCM_C) || \
	defined(MBEDTLS_CCM_C) || \
	defined(MBEDTLS_CHACHAPOLY_C)
	if( mode == MBEDTLS_MODE_GCM ||
		mode == MBEDTLS_MODE_CCM ||
		mode == MBEDTLS_MODE_CHACHAPOLY )
	{
		int ret;
		size_t enc_msglen, olen;
		unsigned char *enc_msg;
		unsigned char add_data[13];
		unsigned char iv[12];
		mbedtls_ssl_transform *transform = ssl->transform_out;
		unsigned char taglen = transform->ciphersuite_info->flags &
							   MBEDTLS_CIPHERSUITE_SHORT_TAG ? 8 : 16;
		size_t explicit_ivlen = transform->ivlen - transform->fixed_ivlen;

		/*
		 * Prepare additional authenticated data
		 */
		memcpy( add_data, ssl->out_ctr, 8 );
		add_data[8]  = ssl->out_msgtype;
		mbedtls_ssl_write_version( ssl->major_ver, ssl->minor_ver,
						   ssl->conf->transport, add_data + 9 );
		add_data[11] = ( ssl->out_msglen >> 8 ) & 0xFF;
		add_data[12] = ssl->out_msglen & 0xFF;

		MBEDTLS_SSL_DEBUG_BUF( 4, "additional data for AEAD", add_data, 13 );

		/*
		 * Generate IV
		 */
		if( transform->ivlen == 12 && transform->fixed_ivlen == 4 )
		{
			/* GCM and CCM: fixed || explicit (=seqnum) */
			memcpy( iv, transform->iv_enc, transform->fixed_ivlen );
			memcpy( iv + transform->fixed_ivlen, ssl->out_ctr, 8 );
			memcpy( ssl->out_iv, ssl->out_ctr, 8 );

		}
		else if( transform->ivlen == 12 && transform->fixed_ivlen == 12 )
		{
			/* ChachaPoly: fixed XOR sequence number */
			unsigned char i;

			memcpy( iv, transform->iv_enc, transform->fixed_ivlen );

			for( i = 0; i < 8; i++ )
				iv[i+4] ^= ssl->out_ctr[i];
		}
		else
		{
			/* Reminder if we ever add an AEAD mode with a different size */
			MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
			return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
		}

		MBEDTLS_SSL_DEBUG_BUF( 4, "IV used (internal)",
								  iv, transform->ivlen );
		MBEDTLS_SSL_DEBUG_BUF( 4, "IV used (transmitted)",
								  ssl->out_iv, explicit_ivlen );

		/*
		 * Fix message length with added IV
		 */
		enc_msg = ssl->out_msg;
		enc_msglen = ssl->out_msglen;
		ssl->out_msglen += explicit_ivlen;

		MBEDTLS_SSL_DEBUG_MSG( 3, ( "before encrypt: msglen = %d, "
									"including 0 bytes of padding",
									ssl->out_msglen ) );

		/*
		 * Encrypt and authenticate
		 */
		if( ( ret = mbedtls_cipher_auth_encrypt( &transform->cipher_ctx_enc,
										 iv, transform->ivlen,
										 add_data, 13,
										 enc_msg, enc_msglen,
										 enc_msg, &olen,
										 enc_msg + enc_msglen, taglen ) ) != 0 )
		{
			MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_auth_encrypt", ret );
			return( ret );
		}

		if( olen != enc_msglen )
		{
			MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
			return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
		}

		ssl->out_msglen += taglen;
		auth_done++;

		MBEDTLS_SSL_DEBUG_BUF( 4, "after encrypt: tag", enc_msg + enc_msglen, taglen );
	}
	else
#endif /* MBEDTLS_GCM_C || MBEDTLS_CCM_C */
#if defined(MBEDTLS_CIPHER_MODE_CBC) &&                                    \
	( defined(MBEDTLS_AES_C) || defined(MBEDTLS_CAMELLIA_C) || defined(MBEDTLS_ARIA_C) )
	if( mode == MBEDTLS_MODE_CBC )
	{
		int ret;
		unsigned char *enc_msg;
		size_t enc_msglen, padlen, olen = 0, i;
		enc_msglen = ssl->out_msglen;
		enc_msg = ssl->out_msg;

#if defined(MBEDTLS_SSL_PROTO_TLS1_1) || defined(MBEDTLS_SSL_PROTO_TLS1_2)
		/*
		 * Prepend per-record IV for block cipher in TLS v1.1 and up as per
		 * Method 1 (6.2.3.2. in RFC4346 and RFC5246)
		 */
		if( ssl->minor_ver >= MBEDTLS_SSL_MINOR_VERSION_2 )
		{
			/*
			 * Generate IV
			 */
			ret = ssl->conf->f_rng( ssl->conf->p_rng, ssl->transform_out->iv_enc,
								  ssl->transform_out->ivlen );
			if( ret != 0 )
				return( ret );
			MBEDTLS_SSL_DEBUG_BUF( 4, "[ICTK] random number iv enc", ssl->transform_out->iv_enc, ssl->transform_out->ivlen );

			memcpy( ssl->out_iv, ssl->transform_out->iv_enc,
					ssl->transform_out->ivlen );

			/*
			 * Fix pointer positions and message length with added IV
			 */
			enc_msg = ssl->out_msg;
			enc_msglen = ssl->out_msglen;
			MBEDTLS_SSL_DEBUG_BUF( 4, "[ICTK]enc msg ==> random number", enc_msg, enc_msglen ); //add the description by hupark...enc_msg output payload 16 byte		
			MBEDTLS_SSL_DEBUG_BUF( 4, "[ICTK]enc msg :", enc_msg, enc_msglen ); //add the description by hupark...enc_msg output payload 16 byte
			MBEDTLS_SSL_DEBUG_BUF( 4, "[ICTK]out iv", ssl->out_iv, ssl->out_msglen);
		}
#endif /* MBEDTLS_SSL_PROTO_TLS1_1 || MBEDTLS_SSL_PROTO_TLS1_2 */

		memcpy( tmp_pseudo_hdr +  0, ssl->out_ctr, 8 ); 							   
		memcpy( tmp_pseudo_hdr +  8, ssl->out_hdr, 3 ); //add the comment by hupark..msgtype+version...
		ret = ictktls_mac_encrypt((const unsigned char* )tmp_pseudo_hdr, ssl->transform_out->iv_enc, random , enc_msg, enc_msglen, crypto , &crypto_len);
		ssl->out_msglen = ssl->transform_out->ivlen + crypto_len;
		memcpy(ssl->out_iv + ssl->transform_out->ivlen , crypto,  crypto_len);
		auth_done++;
		
		MBEDTLS_SSL_DEBUG_BUF( 4, "[ICTK]enc msg", crypto, crypto_len );
		MBEDTLS_SSL_DEBUG_BUF( 4, "[ICTK]total msg", ssl->out_msg, ssl->out_msglen );
		MBEDTLS_SSL_DEBUG_BUF( 4, "[ICTK]enc msg ==> iv", ssl->out_iv, ssl->transform_out->ivlen );
	}
	else
#endif /* MBEDTLS_CIPHER_MODE_CBC &&
          ( MBEDTLS_AES_C || MBEDTLS_CAMELLIA_C || MBEDTLS_ARIA_C ) */
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    /* Make extra sure authentication was performed, exactly once */
    if( auth_done != 1 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= [ICTK]encrypt buf" ) );
#endif
	return 0;

}
	
int ictk_ssl_decrypt_buf( mbedtls_ssl_context *ssl ){
#ifdef ICTK_TLS
	mbedtls_cipher_mode_t mode;
	int auth_done = 0;
    unsigned char pseudo_hdr[11];
    unsigned char crypto[1024];
    unsigned char plain[16];
    int crypto_len = 1024;  
    unsigned char random[16]= {0,};
    unsigned char tmp_mac[MBEDTLS_SSL_MAC_ADD];
	size_t padlen = 0, correct = 1;
	size_t olen = 0;

	
	MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> [ICTK]decrypt buf" ) );

	if( ssl->session_in == NULL || ssl->transform_in == NULL )
	{
		MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
		return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
	}

	mode = mbedtls_cipher_get_cipher_mode( &ssl->transform_in->cipher_ctx_dec );

	if( ssl->in_msglen < ssl->transform_in->minlen )
	{
		MBEDTLS_SSL_DEBUG_MSG( 1, ( "in_msglen (%d) < minlen (%d)",
					   ssl->in_msglen, ssl->transform_in->minlen ) );
		return( MBEDTLS_ERR_SSL_INVALID_MAC );
	}
#if defined(MBEDTLS_ARC4_C) || defined(MBEDTLS_CIPHER_NULL_CIPHER)
    if( mode == MBEDTLS_MODE_STREAM )
    {
        int ret;
        size_t olen = 0;

        padlen = 0;

        if( ( ret = mbedtls_cipher_crypt( &ssl->transform_in->cipher_ctx_dec,
                                   ssl->transform_in->iv_dec,
                                   ssl->transform_in->ivlen,
                                   ssl->in_msg, ssl->in_msglen,
                                   ssl->in_msg, &olen ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_crypt", ret );
            return( ret );
        }

        if( ssl->in_msglen != olen )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }
    }
    else
#endif /* MBEDTLS_ARC4_C || MBEDTLS_CIPHER_NULL_CIPHER */
#if defined(MBEDTLS_GCM_C) || \
    defined(MBEDTLS_CCM_C) || \
    defined(MBEDTLS_CHACHAPOLY_C)
    if( mode == MBEDTLS_MODE_GCM ||
        mode == MBEDTLS_MODE_CCM ||
        mode == MBEDTLS_MODE_CHACHAPOLY ) //This code is not performed...
    {
        int ret;
        size_t dec_msglen, olen;
        unsigned char *dec_msg;
        unsigned char *dec_msg_result;
        unsigned char add_data[13];
        unsigned char iv[12];
        mbedtls_ssl_transform *transform = ssl->transform_in;
        unsigned char taglen = transform->ciphersuite_info->flags &
                               MBEDTLS_CIPHERSUITE_SHORT_TAG ? 8 : 16;
        size_t explicit_iv_len = transform->ivlen - transform->fixed_ivlen;

        /*
         * Compute and update sizes
         */
        if( ssl->in_msglen < explicit_iv_len + taglen )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "msglen (%d) < explicit_iv_len (%d) "
                                "+ taglen (%d)", ssl->in_msglen,
                                explicit_iv_len, taglen ) );
            return( MBEDTLS_ERR_SSL_INVALID_MAC );
        }
        dec_msglen = ssl->in_msglen - explicit_iv_len - taglen;

        dec_msg = ssl->in_msg;
        dec_msg_result = ssl->in_msg;
        ssl->in_msglen = dec_msglen;

        /*
         * Prepare additional authenticated data
         */
        memcpy( add_data, ssl->in_ctr, 8 );
        add_data[8]  = ssl->in_msgtype;
        mbedtls_ssl_write_version( ssl->major_ver, ssl->minor_ver,
                           ssl->conf->transport, add_data + 9 );
        add_data[11] = ( ssl->in_msglen >> 8 ) & 0xFF;
        add_data[12] = ssl->in_msglen & 0xFF;

        MBEDTLS_SSL_DEBUG_BUF( 4, "additional data for AEAD", add_data, 13 );

        /*
         * Prepare IV
         */
        if( transform->ivlen == 12 && transform->fixed_ivlen == 4 )
        {
            /* GCM and CCM: fixed || explicit (transmitted) */
            memcpy( iv, transform->iv_dec, transform->fixed_ivlen );
            memcpy( iv + transform->fixed_ivlen, ssl->in_iv, 8 );

        }
        else if( transform->ivlen == 12 && transform->fixed_ivlen == 12 )
        {
            /* ChachaPoly: fixed XOR sequence number */
            unsigned char i;

            memcpy( iv, transform->iv_dec, transform->fixed_ivlen );

            for( i = 0; i < 8; i++ )
                iv[i+4] ^= ssl->in_ctr[i];
        }
        else
        {
            /* Reminder if we ever add an AEAD mode with a different size */
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

        MBEDTLS_SSL_DEBUG_BUF( 4, "IV used", iv, transform->ivlen );
        MBEDTLS_SSL_DEBUG_BUF( 4, "TAG used", dec_msg + dec_msglen, taglen );

        /*
         * Decrypt and authenticate
         */
        if( ( ret = mbedtls_cipher_auth_decrypt( &ssl->transform_in->cipher_ctx_dec,
                                         iv, transform->ivlen,
                                         add_data, 13,
                                         dec_msg, dec_msglen,
                                         dec_msg_result, &olen,
                                         dec_msg + dec_msglen, taglen ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_auth_decrypt", ret );

            if( ret == MBEDTLS_ERR_CIPHER_AUTH_FAILED )
                return( MBEDTLS_ERR_SSL_INVALID_MAC );

            return( ret );
        }
        auth_done++;

        if( olen != dec_msglen )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }
    }
    else
#endif /* MBEDTLS_GCM_C || MBEDTLS_CCM_C */	
#if defined(MBEDTLS_CIPHER_MODE_CBC) &&                                    \
	( defined(MBEDTLS_AES_C) || defined(MBEDTLS_CAMELLIA_C) || defined(MBEDTLS_ARIA_C) )
	if( mode == MBEDTLS_MODE_CBC )
	{
		/*
		 * Decrypt and check the padding
		 */
		int ret;
		unsigned char *dec_msg;
		unsigned char *dec_msg_result;
		size_t dec_msglen;
		size_t minlen = 0;
		size_t olen = 0;

		/*
		 * Check immediate ciphertext sanity
		 */
#if defined(MBEDTLS_SSL_PROTO_TLS1_1) || defined(MBEDTLS_SSL_PROTO_TLS1_2)
		if( ssl->minor_ver >= MBEDTLS_SSL_MINOR_VERSION_2 )
			minlen += ssl->transform_in->ivlen;
#endif

		if( ssl->in_msglen < minlen + ssl->transform_in->ivlen ||
			ssl->in_msglen < minlen + ssl->transform_in->maclen + 1 )
		{
			MBEDTLS_SSL_DEBUG_MSG( 1, ( "msglen (%d) < max( ivlen(%d), maclen (%d) "
								"+ 1 ) ( + expl IV )", ssl->in_msglen,
								ssl->transform_in->ivlen,
								ssl->transform_in->maclen ) );
			return( MBEDTLS_ERR_SSL_INVALID_MAC );
		}

		dec_msglen = ssl->in_msglen;
		dec_msg = ssl->in_msg;
		dec_msg_result = ssl->in_msg;
#ifdef ICTK_TLS_DEBUG
		MBEDTLS_SSL_DEBUG_BUF( 4, "[ICTK]dec_msg", dec_msg, dec_msglen );

		MBEDTLS_SSL_DEBUG_MSG( 1, ( "msglen (%d)",
					   ssl->transform_in->maclen ) );
#endif
	
		/*
		 * Check length sanity
		 */
		if( ssl->in_msglen % ssl->transform_in->ivlen != 0 )
		{
			MBEDTLS_SSL_DEBUG_MSG( 1, ( "msglen (%d) %% ivlen (%d) != 0",
						   ssl->in_msglen, ssl->transform_in->ivlen ) );
			return( MBEDTLS_ERR_SSL_INVALID_MAC );
		}
	
#if defined(MBEDTLS_SSL_PROTO_TLS1_1) || defined(MBEDTLS_SSL_PROTO_TLS1_2)
		/*
		 * Initialize for prepended IV for block cipher in TLS v1.1 and up
		 */
		if( ssl->minor_ver >= MBEDTLS_SSL_MINOR_VERSION_2 )
		{
			unsigned char i;
			dec_msglen -= ssl->transform_in->ivlen;
			ssl->in_msglen -= ssl->transform_in->ivlen;

			MBEDTLS_SSL_DEBUG_BUF( 4, "[ICTK]dec_msg ", dec_msg, dec_msglen );
			MBEDTLS_SSL_DEBUG_MSG( 1, ( "ivlen (%d) != 0",
						   ssl->transform_in->ivlen) );
			for( i = 0; i < ssl->transform_in->ivlen; i++ )
				ssl->transform_in->iv_dec[i] = ssl->in_iv[i];
#ifdef ICTK_TLS_DEBUG
			MBEDTLS_SSL_DEBUG_BUF( 4, "[ICTK]iv_dec", ssl->transform_in->iv_dec, ssl->transform_in->ivlen );
#endif
		}
	
#endif /* MBEDTLS_SSL_PROTO_TLS1_1 || MBEDTLS_SSL_PROTO_TLS1_2 */

	   
	   memcpy( pseudo_hdr +  0, ssl->in_ctr, 8 );
	   memcpy( pseudo_hdr +  8, ssl->in_hdr, 3 );
	   MBEDTLS_SSL_DEBUG_BUF( 4, "MAC'd meta-data", pseudo_hdr, 11 );
	   memcpy(&crypto[0], dec_msg , dec_msglen); 
	   crypto_len = dec_msglen;

	   ret = ictktls_decrypt_verify((const unsigned char* )pseudo_hdr, ssl->transform_in->iv_dec, random , dec_msg, dec_msglen, dec_msg_result , (int*)&olen);

	   MBEDTLS_SSL_DEBUG_MSG( 1, ( "ictktls_decrypt_verify result (%d)",ret) );
	   auth_done++;
	   ssl->in_msglen = olen;
#ifdef ICTK_TLS_DEBUG
		MBEDTLS_SSL_DEBUG_BUF( 4, "[ICTK]dec_msg_result", dec_msg_result, olen );
#endif
	}
	else
#endif /* MBEDTLS_CIPHER_MODE_CBC &&
		  ( MBEDTLS_AES_C || MBEDTLS_CAMELLIA_C || MBEDTLS_ARIA_C ) */
	{
		MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
		return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
	}

	/* Make extra sure authentication was performed, exactly once */
	if( auth_done != 1 )
	{
		MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
		return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
	}

#if defined(MBEDTLS_SSL_PROTO_DTLS)
	if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
	{
		; /* in_ctr read from peer, not maintained internally */
	}
	else
#endif
	{
		unsigned char i;
		for( i = 8; i > ssl_ep_len( ssl ); i-- )
			if( ++ssl->in_ctr[i - 1] != 0 )
				break;

		/* The loop goes to its end iff the counter is wrapping */
		if( i == ssl_ep_len( ssl ) )
		{
			MBEDTLS_SSL_DEBUG_MSG( 1, ( "incoming message counter would wrap" ) );
			return( MBEDTLS_ERR_SSL_COUNTER_WRAPPING );
		}
	}

	MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= [ICTK]decrypt buf" ) );
#endif
	return( 0 );
}


#ifdef __cplusplus
}
#endif
