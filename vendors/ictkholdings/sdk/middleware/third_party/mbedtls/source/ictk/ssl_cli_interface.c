#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#ifdef ICTK_TLS
#include "g3_api.h"
#endif

#include "ictk/ssl_cli_interface.h"


#ifdef __cplusplus
extern "C" {
#endif
/*
 * Derive and export the shared secret
 */
int ictktls_ecdh_calc_secret(int ecdh_mode, unsigned char *pub, unsigned char *buf, size_t *olen, const unsigned char* ecdh_random, unsigned char* ecdh_value, size_t *ecdh_value_len)
{
	int ret = 0;
#ifdef ICTK_TLS
	ST_ECC_PUBLIC Qb;
	ST_ECC_PUBLIC Qchip;
	byte pre_m_secret[32];	
	ST_ECDH_RANDOM st_ecdh_random ={0,};
	ST_ECDH_KEY_BLOCK st_ecdh_key_block = {0,};

	//printf("[ICTK]ictktls_ecdh_calc_secret\r\n");

	//printf("[ICTK]pre secret\r\n");

	memcpy(Qb.puk , pub , 64 );

	if(ecdh_mode == 0){
		ret = g3api_ecdh(NORMAL_ECDH, &Qb, sizeof(Qb), NULL, &Qchip, pre_m_secret, sizeof(pre_m_secret));
		memcpy( &ecdh_value[0], &pre_m_secret[0], sizeof(pre_m_secret));
	    *ecdh_value_len = 32;
		*olen = 66;
		buf[0] = 0x41;
		buf[1] = 0x04 ;
		memcpy(&buf[2], &Qchip.puk[0], 64);
                
	}
	else if(ecdh_mode == 1){
		memcpy(&st_ecdh_random.client[0], &ecdh_random[0], 32);
		memcpy(&st_ecdh_random.server[0], &ecdh_random[32], 32);
		ret = g3api_ecdh(GEN_TLS_BLOCK , &Qb, sizeof(Qb), &st_ecdh_random , &Qchip , &st_ecdh_key_block , sizeof(ST_ECDH_KEY_BLOCK));

		*olen = 66;
		buf[0] = 0x41;
		buf[1] = 0x04 ;
		memcpy(&buf[2], &Qchip.puk[0], 64);
		
		memcpy( &ecdh_value[0], st_ecdh_key_block.client_mac_key, 32);	
		memcpy( &ecdh_value[32], st_ecdh_key_block.server_mac_key, 32);
		memcpy( &ecdh_value[64], st_ecdh_key_block.client_key, 16);
		memcpy( &ecdh_value[80], st_ecdh_key_block.server_key, 16);
		memcpy( &ecdh_value[96], st_ecdh_key_block.client_iv, 16);
		memcpy( &ecdh_value[112], st_ecdh_key_block.server_iv, 16);
		*ecdh_value_len = 128;
                
	}
#endif
	return ret;
}

#ifdef __cplusplus
}
#endif

