#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#ifdef ICTK_TLS
#include "g3_api.h"
#endif

#include "ictk/aes_interface.h"
#ifdef __cplusplus
extern "C" {
#endif
int ictktls_aes_setkey_enc(int usage, const unsigned char *key,
					unsigned int keybits)
{
	int ret = 0;
	int size = 0;
	unsigned char* tx_buffer[260] = {0,};	
	const unsigned char passwd[] = { 0x11, 0x22, 0x33, 0x44};
#ifdef ICTK_TLS
	// get Root_AC
	ret = g3api_verify_passwd(0, passwd, sizeof(passwd));
	if(ret != 0)
		return ret;
	
#if defined(ICTK_TLS_DEBUG)
	if(ret == 0)
		printf("g3api_verify_passwd success\r\n");
	else		
		printf("g3api_verify_passwd failure\r\n");
#endif

	memset(tx_buffer, 0x00, sizeof(tx_buffer)); 
	memcpy(&tx_buffer[0] ,&key[0], 16);
	size = 32;
	ret = g3api_write_key_value(usage, KEY_AREA, PLAIN_TEXT, &tx_buffer[0], size);
#endif
	return ret;

}

int ictktls_aes_crypt_ecb(       int mode,
                           int usage,
                           const unsigned char input[16],
                           unsigned char output[16])
{
	int ret = 0;	
        int cipher_size = 16;
#ifdef ICTK_TLS
	ST_IV g3_iv;		
	memset(&(g3_iv.iv[0]), 0x00, MBEDTLS_CTR_DRBG_BLOCKSIZE);

	if( mode == MBEDTLS_AES_ENCRYPT )
		ret = g3api_encryption(usage, SECTOR_KEY, BL_CBC, &g3_iv, input, 16, output, &cipher_size);
	else
		ret = g3api_decryption(usage, SECTOR_KEY, BL_CBC, &g3_iv, input, 16, output, &cipher_size);
#endif
	return ret;
}

int ictktls_aes_crypt_cbc(      int mode,
                    int usage,
                    AES_ECB_USE useecb,
                    size_t length,
                    unsigned char iv[16],
                    const unsigned char *input,
                    unsigned char *output)
{
	int ret = 0;
	int i;
	unsigned char temp[16];
	int cipher_size = length;
	
#ifdef ICTK_TLS
	ST_IV g3_iv;

	memcpy(&(g3_iv.iv[0]), &iv[0], 16);
	
	if(useecb == ECB_NONE_USE){

		if( mode == MBEDTLS_AES_ENCRYPT )
			ret = g3api_encryption(usage, SECTOR_KEY, BL_CBC, &g3_iv, input, length, output, &cipher_size);
		else
			ret = g3api_decryption(usage, SECTOR_KEY, BL_CBC, &g3_iv, input, length, output, &cipher_size);
		
	}else{
	
		if( mode == MBEDTLS_AES_DECRYPT )
		{
			while( length > 0 )
			{
				memcpy( temp, input, 16 );
				ictktls_aes_crypt_ecb(mode,usage ,input, output);
	
				for( i = 0; i < 16; i++ )
					output[i] = (unsigned char)( output[i] ^ iv[i] );
	
				memcpy( iv, temp, 16 );
	
				input  += 16;
				output += 16;
				length -= 16;
			}
		}
		else
		{
			while( length > 0 )
			{
				for( i = 0; i < 16; i++ )
					output[i] = (unsigned char)( input[i] ^ iv[i] );
				ictktls_aes_crypt_ecb(mode,usage ,output, output);
	
				memcpy( iv, output, 16 );
	
				input  += 16;
				output += 16;
				length -= 16;
			}
		}
	}
#endif
	return ret;
}
#ifdef __cplusplus
}
#endif
