#ifndef __AES_INTERFACE_HEADER__
#define __AES_INTERFACE_HEADER__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include"g3_define.h"

#define MBEDTLS_AES_ENCRYPT     1 /**< AES encryption. */
#define MBEDTLS_AES_DECRYPT     0 /**< AES decryption. */

#define MBEDTLS_CTR_DRBG_BLOCKSIZE          16 /**< The block size used by the cipher. */

//#define MBEDTLS_CTR_DRBG_KEYSIZE            16 /**< The key size used by the cipher (compile-time choice: 128 bits). */


typedef enum
{
	ECB_NONE_USE = 0,
	ECB_USE = 1,
} AES_ECB_USE;
	
#ifdef __cplusplus
extern "C" {
#endif

int ictktls_aes_setkey_enc(int usage, const unsigned char *key,
                    unsigned int keybits);


int ictktls_aes_crypt_ecb(       int mode,
                    int usage,
                    const unsigned char input[16],
                    unsigned char output[16]);

int ictktls_aes_crypt_cbc(       int mode,
                    int usage,
                    AES_ECB_USE useecb,
                    size_t length,
                    unsigned char iv[16],
                    const unsigned char *input,
                    unsigned char *output);


#ifdef __cplusplus
}
#endif

#endif /* aes_interface.h */
