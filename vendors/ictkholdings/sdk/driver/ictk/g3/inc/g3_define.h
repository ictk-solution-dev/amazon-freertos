//#ifndef __G3_DEFINE_H
//#define __G3_DEFINE_H
//
//#include <stdint.h>
//
///* Defines ------------------------------------------------------------------*/
//
///* I2C Mode Select */
//#define I2C_OD_MODE
////#define I2C_PP_MODE
//
//
//// I2C Wordaddress    
//#define G3_I2C_WORDADDRESS_RESET        0x00
//#define G3_I2C_WORDADDRESS_SLEEP        0x01
//#define G3_I2C_WORDADDRESS_IDLE         0x02
//#define G3_I2C_WORDADDRESS_COMMAND      0x03
//                                        
//// SEND & RECEIVE Retry Count           
//#define G3_SEND_RECEIVE_RETRY_COUNT     3
//#define G3_SEND_RETRY_COUNT             4
//#define G3_RECEIVE_RETRY_COUNT          1000
//                                        
//#define G3_LENGTH_INDEX                 0
//#define G3_INSCODE_INDEX                1
//#define G3_P1_INDEX                     2
//#define G3_P2_INDEX_1                   3
//#define G3_P2_INDEX_2                   4
//#define G3_DATA_INDEX          	        5
//                                        
//#define G3_CRC_SIZE                     2
//#define G3_RSPLEN_CRC_SIZE              3
//                                        
//                                        
//#define G3_RSP_SIZE_MAX                 253
//                                        
//                                        
//#define WAKE_LOW_DURATION               100
//                                        
//#define EXEC_MIN_DELAY                  1
//
//// G3 I/O Error Code
//#define G3_OK                           0x00000000
//#define ERR_GENERAL                     0x80000000
//#define ERR_INTERCHIP                   0xF0000000
//#define ERR_COMMUNICATION               0xFF000000
//
//#define G3_ERR_RSP_SIZE                                ERR_GENERAL|0xF0
//#define G3_ERR_INVALID_PARAMETER                       ERR_GENERAL|0xF1
//#define G3_ERR_DIFF_RSP_SIZE                           ERR_GENERAL|0xF2
//#define G3_ERR_RECV_ALLOC_ERROR                        ERR_GENERAL|0xF3
//#define G3_ERR_RET_SIZE                                ERR_GENERAL|0xF4
//#define G3_ERR_BUSY                                    ERR_GENERAL|0xF5 
//  
//#define G3_ERR_INTERCHIP_INS_FAIL                      ERR_INTERCHIP|0x01
//#define G3_ERR_INTERCHIP_PARSE_ERROR                   ERR_INTERCHIP|0x03
//#define G3_ERR_INTERCHIP_EXECUTION_ERROR               ERR_INTERCHIP|0x0F
//#define G3_ERR_INTERCHIP_WAKE_UP_ERROR                 ERR_INTERCHIP|0x11
//#define G3_ERR_INTERCHIP_COMMUNICATION_ERROR           ERR_INTERCHIP|0xFF
//#define G3_ERR_INTERCHIP_ABNORMAL_INPUT_DETECTION      ERR_INTERCHIP|0x21
//
//#define G3_ERR_COMM_I2C_MTK_WRITE                      ERR_COMMUNICATION|0xA1
//#define G3_ERR_COMM_I2C_MTK_READ                       ERR_COMMUNICATION|0xA2
//
//
//#endif /*__G3_DEFINE_H*/





#ifndef __G3_DEFINE_HEADER__
#define __G3_DEFINE_HEADER__

#include <stdint.h>
#define CALLTYPE

#ifdef __cplusplus 
#define G3_API extern "C" 
#else
#define G3_API
#endif 



/* I2C Mode Select */
#define I2C_OD_MODE
//#define I2C_PP_MODE


// I2C Wordaddress    
#define G3_I2C_WORDADDRESS_RESET        0x00
#define G3_I2C_WORDADDRESS_SLEEP        0x01
#define G3_I2C_WORDADDRESS_IDLE         0x02
#define G3_I2C_WORDADDRESS_COMMAND      0x03

// SEND & RECEIVE Retry Count           
#define G3_SEND_RECEIVE_RETRY_COUNT     3
#define G3_SEND_RETRY_COUNT             4
#define G3_RECEIVE_RETRY_COUNT          1000

#define G3_LENGTH_INDEX                 0
#define G3_INSCODE_INDEX                1
#define G3_P1_INDEX                     2
#define G3_P2_INDEX_1                   3
#define G3_P2_INDEX_2                   4
#define G3_DATA_INDEX          	        5

#define G3_CRC_SIZE                     2
#define G3_RSPLEN_CRC_SIZE              3


// Response Size definitions
#define G3_CMD_SIZE_MIN                7
#define G3_CMD_SIZE_MAX                84

#define G3_RSP_SIZE_MAX                 256//253


#define WAKE_LOW_DURATION               100

#define EXEC_MIN_DELAY                  1

// G3 I/O Error Code
#define G3_OK                           0x00000000
#define ERR_GENERAL                     0x80000000
#define ERR_INTERCHIP                   0xF0000000
#define ERR_COMMUNICATION               0xFF000000

#define G3_ERR_RSP_SIZE                                ERR_GENERAL|0xF0
#define G3_ERR_INVALID_PARAMETER                       ERR_GENERAL|0xF1
#define G3_ERR_DIFF_RSP_SIZE                           ERR_GENERAL|0xF2
#define G3_ERR_RECV_ALLOC_ERROR                        ERR_GENERAL|0xF3
#define G3_ERR_RET_SIZE                                ERR_GENERAL|0xF4
#define G3_ERR_BUSY                                    ERR_GENERAL|0xF5 

#define G3_ERR_INTERCHIP_INS_FAIL                      ERR_INTERCHIP|0x01
#define G3_ERR_INTERCHIP_PARSE_ERROR                   ERR_INTERCHIP|0x03
#define G3_ERR_INTERCHIP_EXECUTION_ERROR               ERR_INTERCHIP|0x0F
#define G3_ERR_INTERCHIP_WAKE_UP_ERROR                 ERR_INTERCHIP|0x11
#define G3_ERR_INTERCHIP_COMMUNICATION_ERROR           ERR_INTERCHIP|0xFF
#define G3_ERR_INTERCHIP_ABNORMAL_INPUT_DETECTION      ERR_INTERCHIP|0x21

#define G3_ERR_COMM_I2C_MTK_WRITE                      ERR_COMMUNICATION|0xA1
#define G3_ERR_COMM_I2C_MTK_READ                       ERR_COMMUNICATION|0xA2



//START DEFINE
#define LIB_VERSION  "1.1.0"

#define RET_SUCCESS 0x00
#define ERR_GENERAL 0x80000000
#define ERR_INTERCHIP 0xF0000000

#define RET_ERR_RECV_BUFF_SIZE ERR_GENERAL|0xF0
#define RET_ERR_KEY_BUFF_SIZE ERR_GENERAL|0xF1
#define RET_ERR_RECV_CRC_ERROR ERR_GENERAL|0xF2
#define RET_ERR_SIGN_MODE_PARSE_ERR ERR_GENERAL|0xF3
#define RET_ERR_DIFF_STRUCT_SIZE ERR_GENERAL|0xF4
#define RET_ERR_RECV_ALLOC_ERROR ERR_GENERAL|0xF5
#define RET_ERR_RET_SIZE ERR_GENERAL|0xF6

#define RET_ERR_INTERCHIP_VERIFY_ERROR ERR_INTERCHIP|0x01
#define RET_ERR_INTERCHIP_PARSE_ERROR ERR_INTERCHIP|0x03
#define RET_ERR_INTERCHIP_EXECUTION_ERROR ERR_INTERCHIP|0x0F
#define RET_ERR_INTERCHIP_AFTER_WAKE_UP ERR_INTERCHIP|0x11
#define RET_ERR_INTERCHIP_COMMUNICATIONS_ERROR ERR_INTERCHIP|0xFF
#define RET_ERR_INTERCHIP_ABNORMAL_INPUT_DETECTION ERR_INTERCHIP|0x21

//#define NULL 0
#define IN 
#define OUT 
#define INOUT 
//END DEFINE


//START ENUM

typedef enum  
{
	SND_N_RECV=0,
	SND=1,
	RECV=2,	 
}  EN_SND_RECV_MODE;   	

typedef enum  
{
	AND=0,
	OR=1,	 
}  EN_AND_OR;   	

typedef enum  
{
	CONDITION=0,
	FREE=1,
	FORBIDDEN=2,	 
}  EN_FORBIDDEN_TYPE;   	

typedef enum  
{
	ALL=0,
	MASK_N_ENC =1,
	ENC=2,
	ENC_MAC=3,	 
}  EN_RW ;   	

typedef enum  
{
	SECT_VOID=0,
	SECT_ST_ECC_PUF=1,
	SECT_ECC_PRV=2,
	SECT_ECC_PUB=3,
	SECT_AES128=4,
	SECT_AES256=5,
	SECT_SM4=6,
	SECT_SHA256=7,
	SECT_PASSWORD=8,
	SECT_DATA=9,
	SECT_COUNTER=10,	 
}  EN_DATA_SECTOR_TYPE;   	

typedef enum  
{
	SUCCESS_=0,
	FAIL=-1,	 
}  EN_RESULT;   	

typedef enum  
{
	INHERIT=0,
	SELF=1,	 
}  EN_DIVERSIFY_MODE;   	

typedef enum
{
	SECTOR_KEY = 0,
	SESSION_KEY = 1,
} EN_KEY_TYPE;

typedef enum  
{
	BL_CBC=0,
	BL_CTR=1,
	BL_GCM=3,	 
}  EN_BLOCK_MODE;   	

typedef enum  
{
	TO_TEMP=0,
	TO_KEY_SECTOR=1,	 
}  EN_CERTIFICATION_WRITE_MODE;   	

typedef enum  
{
	SIGN_ECDSA_EXT_SHA256=0,
	SIGN_SM2sign_EXT_SM3=0,
	SIGN_ECDSA_WITH_SHA256=1,
	SIGN_SM2sign_WITH_SM3 = 1,
	SIGN_HMAC=2,
	SIGN_SYMM=3,	 
	SIGN_SESSION_SYMM=4,
}  EN_SIGN_OPTION;   	

typedef enum  
{
	VERIFY_ECDSA_EXT_SHA256=0,
	VERIFY_SM2_EXT_SM3=0,
	VERIFY_ECDSA_WITH_SHA256=1,
	VERIFY_SM2_WITH_SM3=1,
	VERIFY_HMAC=2,
	VERIFY_SYMM=3,
	VERIFY_SESSION_SYMM=4,
	VERIFY_EXT_PUB_ECDSA_EXT_SHA256=0x10,
	VERIFY_EXT_PUB_SM2_EXT_SM3 = 0x10,
	VERIFY_EXT_PUB_ECDSA_WITH_SHA256=0x11,	
	VERIFY_EXT_PUB_SM2_WITH_SM3 = 0x11,
}  EN_VERIFY_OPTION;   	

typedef enum  
{
	DYN_AUTH_ECDSA_SHA256=0x21,
	DYN_AUTH_SM2_SM3 = 0x21,
	DYN_AUTH_HMAC=0x22,
	DYN_AUTH_SYMM=0x23,
	DYN_AUTH_CERT_PUB_ECDSA_SHA256=0x31,	 
	DYN_AUTH_CERT_PUB_SM2_SM3 = 0x31,
}  EN_DYNAMIC_AUTH;   	

typedef enum  
{
	USE_CERT_PUB_ECDSA_EXT_SHA256=0,
	USE_CERT_PUB_ECDSA_WITH_SHA256=1,	 
}  EN_VERIFY_TYPE;   	

typedef enum  
{
	SETUP_AREA=0,
	KEY_AREA=1,
	DATA_AREA_0=2,
	DATA_AREA_1=3,	 
}  EN_AREA_TYPE;   	

typedef enum  
{
	PLAIN_TEXT=0,
	CBC=1,
	CTR=2,
	CCM=3,
	GCM=4,
	CBC_with_MAC=5,
	CTR_with_MAC=6,
	SESSION_KEY_CBC=0x11,
	SESSION_KEY_CTR=0x12,
	SESSION_KEY_CCM=0x13,
	SESSION_KEY_GCM=0x14,
	SESSION_KEY_CBC_with_MAC=0x15,
	SESSION_KEY_CTR_with_MAC=0x16,
	MASKED=0xFF,	 
}  EN_RW_INST_OPTION;   	

typedef enum  
{
	KEY_SECTOR=0,
	TEMP_PUBLIC_KEY=1,	 
}  EN_PUB_TYPE;   	

typedef enum  
{
	ISCRT_KEY_AREA=0,
	ISCRT_DATA_AREA_0=1,
	ISCRT_DATA_AREA_1=2,	 
}  EN_ISSUE_CERT_AREA_TYPE;   	

typedef enum  
{
	CHANGE_CIPHER_SPEC=20,
	ALERT=21,
	HANDSHAKE=22,
	APPLICATION_DATA=23,	 
}  EN_CONTENT_TYPE;   	

typedef enum  
{
	SSL_3_0=0x0300,
	TLS_1_0=0x0301,
	TLS_1_1=0x0302,
	TLS_1_2=0x0303,	 
}  EN_TLS_VERSION;   	

typedef enum  
{
	NORMAL_ECDH=0x0000,
	GEN_TLS_BLOCK=0x0011,
	SET_TLS_SESSION_KEY=0x0012,	 
}  EN_ECDH_MODE;   	

typedef enum  
{
	SYMM_KEY=0x80,
	FACTORY_AES=0x90,
	FACTORY_SM4=0x91,
	EXT_SESSION_KEY_AES=0xA0,
	EXT_SESSION_KEY_SM4=0xA1,
	EXT_PUB_KEY=0xA2,	 
}  EN_SESSION_MODE;   	

typedef enum  
{
	HSM_CLIENT=0x0000,
	HSM_SERVER=0x0001,	 
}  EN_HANDSHAKE_MODE;   	

typedef enum  
{
	SHA256_Initialize =0x0000,
	SHA256_Update=0x0001,
	SHA256_Finalize=0x00FF,
}  EN_SHA256_MODE;   	

typedef enum
{
	SM3_Initialize = 0x0000,
	SM3_Update = 0x0001,
	SM3_Finalize = 0x00FF,
}  EN_SM3_MODE;



//END ENUM







//START TYPE_DEF

typedef unsigned int dword;
typedef unsigned short word;
typedef unsigned char byte;

typedef int(CALLTYPE *PFSENDRECV) (const unsigned char*,int,unsigned char*,int*,  void*etcparam );
typedef int G3_API_RESULT;
typedef int(CALLTYPE *PFTEST) (int param);
//END TYPE_DEF




//START STRUCTURE

#pragma pack(push, 1)

typedef struct _tagVAR_BYTES{
	int size;
	int allocsize;
	byte buffer[1];
}VAR_BYTES, *LPVAR_BYTES;

typedef struct _tagST_SIGN_ECDSA{
	byte r[32];
	byte s[32];
}ST_SIGN_ECDSA, *LPST_SIGN_ECDSA;

typedef struct _tagST_SIGN_SM2{
	byte r[32];
	byte s[32];
}ST_SIGN_SM2, *LPST_SIGN_SM2;

typedef struct _tagST_SIGN_SYMM{
	byte sign[16];
}ST_SIGN_SYMM, *LPST_SIGN_SYMM;

typedef struct _tagST_SIGN_HMAC{
	byte sign[32];
}ST_SIGN_HMAC, *LPST_SIGN_HMAC;

typedef struct _tagST_ECC_PUBLIC{
	byte puk[64];
}ST_ECC_PUBLIC, *LPST_ECC_PUBLIC;

typedef struct _tagST_ECC_PUBLIC_COMPRESS{
	byte puk[33];
}ST_ECC_PUBLIC_COMPRESS, *LPST_ECC_PUBLIC_COMPRESS;

typedef struct _tagST_ECC_PRV{
	byte prk[32];
}ST_ECC_PRV, *LPST_ECC_PRV;

typedef struct _tagST_DIVERSIFY_PARAM{
	byte param[16];
}ST_DIVERSIFY_PARAM, *LPST_DIVERSIFY_PARAM;

typedef struct _tagST_KEY_VALUE{
	byte key_value[32];
}ST_KEY_VALUE, *LPST_KEY_VALUE;

typedef struct _tagST_IV{
	byte iv[16];
}ST_IV, *LPST_IV;

typedef struct _tagST_RW_DATA{
	byte data[32];
}ST_RW_DATA, *LPST_RW_DATA;

typedef struct _tagST_RW_DATA_WITH_IV{
	byte data[32];
	byte iv[16];
}ST_RW_DATA_WITH_IV, *LPST_RW_DATA_WITH_IV;

typedef struct _tagST_RW_DATA_WITH_IV_MAC{
	byte data[32];
	byte iv[16];
	byte mac[16];
}ST_RW_DATA_WITH_IV_MAC, *LPST_RW_DATA_WITH_IV_MAC;

typedef struct _tagST_RW_DATA_WITH_MASK{
	byte data[32];
	byte mask[32];
}ST_RW_DATA_WITH_MASK, *LPST_RW_DATA_WITH_MASK;

typedef struct _tagST_ECIES{
	byte r[64];
	byte s[32];
}ST_ECIES, *LPST_ECIES;

typedef struct _tagST_ECIES_XY{
	byte r[64];
	byte p[64];
}ST_ECIES_XY, *LPST_ECIES_XY;

typedef struct _tagST_SM2_C1{
	byte c1[64];
}ST_SM2_C1, *LPST_SM2_C1;

typedef struct _tagST_SM2_C3{
	byte c3[32];
}ST_SM2_C3, *LPST_SM2_C3;

typedef struct _tagST_AC_CONDITION{
	EN_AND_OR and_or;
	EN_FORBIDDEN_TYPE forbidden_type;
	short key_number[2];
}ST_AC_CONDITION, *LPST_AC_CONDITION;

typedef struct _tagST_KEY_SECTOR{
	EN_DATA_SECTOR_TYPE data_sector_type;
	EN_RW rw;
	ST_AC_CONDITION ac_cond[3];
}ST_KEY_SECTOR, *LPST_KEY_SECTOR;

typedef struct _tagST_SETUP_CORE{
	ST_KEY_SECTOR root;
	ST_KEY_SECTOR data_0;
	ST_KEY_SECTOR data_1;
}ST_SETUP_CORE, *LPST_SETUP_CORE;

typedef struct _tagST_SET_UP_VALUE{
	int setup_sector_index;
	ST_KEY_SECTOR key_sector;
	ST_KEY_VALUE value;
	EN_RESULT result_setup_area;
	EN_RESULT result_write_value;
}ST_SET_UP_VALUE, *LPST_SET_UP_VALUE;

typedef struct _tagST_ECDH_PRE_MASTER_SECRET{
	byte pre_master_secret[32];
}ST_ECDH_PRE_MASTER_SECRET, *LPST_ECDH_PRE_MASTER_SECRET;

typedef struct _tagST_ECDH_KEY_BLOCK{
	byte client_mac_key[32];
	byte server_mac_key[32];
	byte client_key[16];
	byte server_key[16];
	byte client_iv[16];
	byte server_iv[16];
}ST_ECDH_KEY_BLOCK, *LPST_ECDH_KEY_BLOCK;

typedef struct _tagST_ECDH_IV{
	byte client_iv[16];
	byte server_iv[16];
}ST_ECDH_IV, *LPST_ECDH_IV;

typedef struct _tagST_ECDH_RANDOM{
	byte server[32];
	byte client[32];
}ST_ECDH_RANDOM, *LPST_ECDH_RANDOM;

typedef struct _tagST_DATA_16{
	byte data[16];
}ST_DATA_16, *LPST_DATA_16;

typedef struct _tagST_DATA_32{
	byte data[32];
}ST_DATA_32, *LPST_DATA_32;

typedef struct _tagST_DATA_64{
	byte data[64];
}ST_DATA_64, *LPST_DATA_64;

typedef struct _tagST_DATA_128{
	byte data[128];
}ST_DATA_128, *LPST_DATA_128;

typedef struct _tagST_TLS_INTER_HEADER_WITHOUT_SIZE{
	dword hi_be_sequence;
	dword lo_be_sequence;
	byte content_type;
	word tls_be_ver;
}ST_TLS_INTER_HEADER_WITHOUT_SIZE, *LPST_TLS_INTER_HEADER_WITHOUT_SIZE;

typedef struct _tagST_TLS_INTER_HEADER{
	ST_TLS_INTER_HEADER_WITHOUT_SIZE tls_inter_header_without_size;
	word msg_be_size;
}ST_TLS_INTER_HEADER, *LPST_TLS_INTER_HEADER;

typedef struct _tagST_TLS_HAND_HANDSHAKE_DIGEST{
	byte data[12];
}ST_TLS_HAND_HANDSHAKE_DIGEST, *LPST_TLS_HAND_HANDSHAKE_DIGEST;
   
#pragma pack(pop)  
	//END STRUCTURE


#endif//__G3_DEFINE_HEADER__


