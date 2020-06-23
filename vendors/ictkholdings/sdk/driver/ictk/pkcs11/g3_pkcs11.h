
#ifndef __G3_PKCS11_HEADER__
#define __G3_PKCS11_HEADER__


#ifdef G3_PKCS11   

#define G3_PROFILE_LENGTH               32
#define G3_ECC_PUBKEY_LENGTH            64
#define G3_PROFILE_STRING_MAX           20

#define G3_PKCS11_PRV_KEY_SECTOR        104
#define G3_PKCS11_PUB_KEY_SECTOR        105

#define G3_PKCS11_PRV_PROFILE_SECTOR     8
#define G3_PKCS11_PUB_PROFILE_SECTOR     9
#define G3_PKCS11_CERT_PROFILE_SECTOR    10


typedef enum {
    G3_ECC_PRIV_KEY = 0x00,
    G3_ECC_PUB_KEY  = 0x01,
    G3_ECC_CERT     = 0x02,
    G3_ZERO         = 0x03,
} g3_pkcs11_data_type_t;


int pkcs11_data_write(char* filename, uint8_t* data, uint32_t datalen, g3_pkcs11_data_type_t type);

int pkcs11_data_read(char* filename, uint8_t* data, uint32_t* datalen);

#endif  // G3_PKCS11   

#endif //__G3_PKCS11_HEADER__






