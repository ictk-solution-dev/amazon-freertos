#ifndef __PROFILE_HEADER__
#define __PROFILE_HEADER__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "x509_crt.h"

#include"g3_define.h"
#ifdef __cplusplus
	extern "C" {
#endif

#define WHITELIST_MAX_SIZE			10
#define START_INDEX_WHITELIST 		100//0x10
          

typedef enum  
{
	CA = 0,
	CLIENT=1,
	SERVER=2,
	SIGNER_CA = 3,
#ifdef G3_PKCS11
        PKCS_PRV=4,
        PKCS_PUB=5,
        PKCS_CERT=6,
#endif
} KEYUSAGE;  

/**
 * \brief       set the information of profile for tls
 *             
 *
 * \param profDesc   describe the profile   
 * \param defCount   the number of certificate to used
 * \param whiteListLoc   The location that whithlist is saved
 * \param whiteListStIndex   The position for whitelist
 *
 * \return      0 if successful
 */

int set_tls_header_profile(char* profDesc, uint8_t* defCount, uint8_t* whiteListLoc, uint8_t* whiteListStIndex);
/**
 * \brief       get the information of profile for tls
 *             
 *
 * \param profDesc   describe the profile   
 * \param defCount   the number of certificate to used
 * \param whiteListLoc   The location that whithlist is saved
 * \param whiteListStIndex   The position for whitelist
 *
 * \return      0 if successful
 */

int get_tls_header_profile(char* profDesc, uint8_t* defCount, uint8_t* whiteListLoc, uint8_t* whiteListStIndex);

/**
 * \brief       set the information of profile
 *             
 *
 * \param keyusagemode   the mode for key usage
 * \param sectornum   the sector number to save any information    
 * \param key_information   the full information
 * \param keyusage   the type of key
 * \param keystate   the current state of key
 * \param caseDesc   decrible
 * \param pri_info   the information of private key
 * \param certinfo   the information of certificate
 *
 * \return      0 if successful
 */

int set_tls_profile(KEYUSAGE keyusagemode, uint8_t sectornum, uint8_t* key_information, uint8_t len,
uint8_t* keyusage, uint8_t* keystate, uint8_t* keytype, char* caseDesc, uint8_t* pri_info,uint8_t* certinfo, uint8_t* prov_flag );

/**
 * \brief       set the flag of provisioning
 *             
 *
 * \param keyusagemode   the mode for key usage
 * \param sectornum   the sector number to save any information    
 * \param provisioning   the flag of provisioning
 *
 * \return      0 if successful
 */

int set_tls_provisioning_profile(KEYUSAGE keyusagemode, uint8_t sectornum, uint8_t* provisioning);


/**
 * \brief       get the information of profile
 *             
 *
 * \param keyusagemode   the mode for key usage
 * \param sectornum   the sector number that any informations is saved in    
 * \param key_information   the key information for profile
 * \param len   			the length of key information
 *
 * \return      0 if successful
 */

int get_tls_profile(KEYUSAGE keyusagemode, uint8_t sectornum, uint8_t* key_information, uint8_t len);


/**
 * \brief       get the flag of provisioning
 *             
 *
 * \param keyusagemode   the mode for key usage
 * \param sectornum   the sector number that the flag of provisioning is saved in    
 * \param key_information   the key information for profile
 * \param len   			the length of key information
 *
 * \return      0 if successful
 */

int get_tls_provisioning_profile(KEYUSAGE keyusagemode, uint8_t sectornum, uint8_t* provisioning);

/**
 * \brief      set whitelist
 *             
 *
 * \param startWhitelistIndex   the sector number that any informations is saved in    
 * \param index_size   			the maximum size of index to save whitelist
 * \param cert   				the certificate to get whitelist
 * \param certlen   			the length of certificate
 *
 * \return      0 if successful
 */

int set_tls_whitelist(uint8_t startWhitelistIndex, uint8_t index_size, uint8_t* cert, size_t certlen, char* _cn, int _cn_len, int withCN);

/**
 * \brief      set whitelist
 *             
 *
 * \param startWhitelistIndex   the sector number that any informations is saved in    
 * \param index_size   			the maximum size of index that the whitelist is saved
 * \param whitelist   			the information of whitelist that is saved
 * \param whitelistlen   		the length of whitelist
 *
 * \return      0 if successful
 */

int get_tls_whitelist(uint8_t startWhitelistIndex, uint8_t index_size, uint8_t* whitelist, size_t whitelistlen);

int get_tls_whitelist2(uint8_t index, uint8_t* whitelist, size_t whitelistlen);

/**
 * \brief      get the name of whitelist
 *             
 *
 * \param name  			the buffer for cn     
 * \param cn   				name of cn
 * \param cn_len   			length of cn
 *
 * \return      0 if successful
 */
static int x509_crt_get_cn( const mbedtls_x509_buf *name, char *cn, size_t* cn_len );

/**
 * \brief      parse the cn in certificate
 *             
 *
 * \param crt   			certificate    
 * \param cn   				name of cn
 * \param cn_len   			length of cn
 *
 * \return      0 if successful
 */

static void x509_crt_parse_cn( const mbedtls_x509_crt *crt, char *cn, size_t* cn_len);

/**
 * \brief      initialize whitelist
 *             
 *
 * \param startWhitelistIndex   	the first position to save the whitelist     
 * \param index_size   				the maximum size of whitelist
 *
 * \return      0 if successful
 */

int init_tls_whitelist(uint8_t startWhitelistIndex, uint8_t index_size);

/**
 * \brief      set key state
 *             
 *
 * \param keyusagemode   the mode for key usage
 * \param sectornum   	the sector number is saved any informations     
 * \param keystate 	    the key state
 *
 * \return      0 if successful
 */

int set_tls_keystate(KEYUSAGE keyusagemode, uint8_t sectornum, uint8_t keystate);

/**
 * \brief	   get key state
 *			   
 *
 * \param keyusagemode   the mode for key usage
 * \param sectornum 	the sector number is saved any informations 	
 *
 * \return		key state if successful
 */

uint8_t get_tls_keystate(KEYUSAGE keyusagemode, uint8_t sectornum);

/**
 * \brief	   get sector number of cert
 *			   
 *
 * \param keyusagemode   the mode for key usage
 * \param sectornum 	the sector number is saved any informations 	
 *
 * \return		key state if successful
 */

int get_tls_cert_end_sector(KEYUSAGE keyusagemode, uint8_t sectornum, uint8_t* end_sector);

int get_cert_from_profile(KEYUSAGE keyusagemode, uint8_t* cert, int* certlen);

#ifdef __cplusplus
}
#endif

#endif /* profile.h */
