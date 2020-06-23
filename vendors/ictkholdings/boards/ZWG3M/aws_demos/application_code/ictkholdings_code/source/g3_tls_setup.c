/* Copyright Statement:
 *
 * (C) G3 NVDM Configure  
 *  2019 -09-10 
 *  ZN tehnologies 
 *  G3 related parameters will be stored 
 *  amazon info added to amazon group 
 *
 */

#include <stdio.h>
#include <string.h>
#include "FreeRTOS.h"
#include "nvdm.h"
#include "syslog.h"
#include "connsys_profile.h"
#include "connsys_util.h"
#include "get_profile_string.h"
#include "g3_define.h"
#include "type_def.h"
#include "g3_cert.h"
#include "g3_tls_setup.h"
#include "iot_default_root_certificates.h"
#include "ictk\profile.h"
#include "g3_nvdm_config.h"
#include "aws_clientcredential_keys.h"




#if (defined(ICTK_TLS) && defined(ICTK_TLS_FOR_AWSTEST))

int certificate_data_sector_alloc;

#define G3_PEM_EC_HEADER        "-----BEGIN EC PRIVATE KEY-----"
#define G3_PEM_EC_FOOTER        "-----END EC PRIVATE KEY-----"
#define G3_CERT_HEADER        "-----BEGIN CERTIFICATE-----"
#define G3_CERT_FOOTER        "-----END CERTIFICATE-----"

int g3_send_recv_(const unsigned char* sBuf, int sBufLen, unsigned char* rBuf, int* rBufLen, void* etcparam )
{
  return puf_sendNRecv( (uint8_t*) sBuf, (uint32_t) sBufLen, (uint8_t*) rBuf, (uint32_t*) rBufLen );
}


static unsigned char* delete_header_footer(unsigned char *data, int *size)
{
  unsigned char* start_address = NULL;
  unsigned char* end_address = NULL;
  
  
  start_address = strstr(data, G3_PEM_EC_HEADER);               //prvkey
  end_address = strstr(data, G3_CERT_HEADER);                   //cert
    
  if(start_address != NULL)
  {
      start_address = strstr(data, G3_PEM_EC_HEADER);
      end_address = strstr(data, G3_PEM_EC_FOOTER);
      start_address += strlen(G3_PEM_EC_HEADER);
  }
  else if(end_address != NULL)
  {
      start_address = strstr(data, G3_CERT_HEADER);
      end_address = strstr(data, G3_CERT_FOOTER);
      start_address += sizeof(G3_CERT_HEADER);
  }  
  else
    return NULL;
  
  
  *size = end_address - start_address;
  return start_address;
}


static int tls_setup()
{
	//ST_KEY_VALUE recv_key;
	ST_KEY_VALUE write_key;
	uint32_t size = 0;
        int cert_size = 0;
	int ret = 0;
	uint8_t tx_buffer[260] = {0,};
        //unsigned char cert_base64[1000];
        unsigned char prvkey_base64[500];
        
        unsigned char prvkey[32];
        int prvlen, prvlen_base64;
        int certlen, certlen_base64;
        certificate_data_sector_alloc = 0;
        
        static const char *base64_client_prvkey = keyCLIENT_PRIVATE_KEY_PEM;
        unsigned char *base64_address;
        ST_KEY_VALUE recv_key_information;
#if 1   //profile
        uint8_t keyusage[1] = {0,};
	uint8_t keytype[1] = {0,};
	uint8_t keystate[1] = {0,};
	uint8_t priInfo[4] = {0,};
	uint8_t certInfo[4] = {0,};
        uint8_t cert_offset = 0x00;
        uint8_t prov_flag = 0x99;
#endif
        
        
        //--- Password ------------------------------------------------------------------------------  
	const unsigned char passwd[] = { 0x11, 0x22, 0x33, 0x44};
        
	ret = g3api_verify_passwd(0, passwd, sizeof(passwd));
        if(ret != G3_OK)
        {
		return ret;
	}

        //--- Key Area Setup (password) ---------------------------------------------------------------
	memset(tx_buffer, 0x00, sizeof(tx_buffer));
	size = set_buffer_from_hexstr(tx_buffer,(const char*)"8E540000000000004E540000000000004E540000000000004E54000000000000");
	ret = g3api_write_key_value(4, SETUP_AREA, PLAIN_TEXT, &tx_buffer[0], size);
        if(ret != G3_OK)
        {
		return ret;
	}

        //--- Key Write (password) -------------------------------------------------------------------
	memset(tx_buffer, 0x00, sizeof(tx_buffer));
	size = set_buffer_from_hexstr(tx_buffer,(const char*)"0405050511223344000000000000000000000000000000000000000000000000");
	ret = g3api_write_key_value(0, KEY_AREA, PLAIN_TEXT, &tx_buffer[0], size);
        if(ret != G3_OK)
        {
          return ret;
        }
  
        //--- Root Setup (Get AC by key sector 0(password)) -------------------------------------------------------------------
	memset(tx_buffer, 0x00, sizeof(tx_buffer));
	size = set_buffer_from_hexstr(tx_buffer,(const char*)"0E00000000000000005400000000000000540000000000000054000000000000");
	ret = g3api_write_key_value(2, SETUP_AREA, PLAIN_TEXT, &tx_buffer[0], size);
        if(ret != G3_OK)
        {
          return ret;
        }
#if G3_CLIENT_CERT_PRIVKEY_KEYSECTOR == 114
        //--- Key Area Setup (Client Certificate private key) -------------------------------------------------------------------
	memset(tx_buffer, 0x00, sizeof(tx_buffer));
	size = set_buffer_from_hexstr(tx_buffer,(const char*)"005400000000000000540000000000002E540000000000003E54000000000000");
	ret = g3api_write_key_value(4+(G3_CLIENT_CERT_PRIVKEY_KEYSECTOR/4), SETUP_AREA, PLAIN_TEXT, &tx_buffer[0], size);
        if(ret != G3_OK)
        {
          return ret;
        }

        ictktls_set_puf_priv_index(G3_CLIENT_CERT_PRIVKEY_KEYSECTOR);
#else
#error   "G3_CLIENT_CERT_PRIVKEY_KEYSECTOR" must be 114
#endif
         //--- Key Write (Client Certificate private key) -------------------------------------------------------------------
        base64_address = NULL;
        base64_address = delete_header_footer(keyCLIENT_PRIVATE_KEY_PEM, &prvlen_base64);
        if(base64_address == NULL)
        {
            printf("Client Certificate Private Key format is wrong.\n");
            return -1;
        }
        
        
        ret = mbedtls_base64_decode( prvkey_base64, sizeof( prvkey_base64 ), &prvlen, base64_address, prvlen_base64);
        if(ret != 0 )
        {
          return ret;
        }
        memcpy(prvkey, prvkey_base64+7, 32);
        memset(tx_buffer, 0x00, sizeof(tx_buffer));
        memcpy(tx_buffer, prvkey, size);
        size = sizeof(prvkey);
        
	ret = g3api_write_key_value(G3_CLIENT_CERT_PRIVKEY_KEYSECTOR, KEY_AREA, PLAIN_TEXT, &tx_buffer[0], size);
        if(ret != G3_OK)
        {
          return ret;
        }

        //--- Certificate Write (Client) -------------------------------------------------------------------
        cert_size = strlen(keyCLIENT_CERTIFICATE_PEM) + 1;
        for(int i =0; i< (((cert_size-1)/32)+1); i++)
        {
            memset(tx_buffer, 0x00, sizeof(tx_buffer));
            if((i+1)*32 > cert_size)
              size = cert_size - 32*i;
            else
              size = 32;
            
            memcpy(tx_buffer, keyCLIENT_CERTIFICATE_PEM+32*i, size);
            ret = g3api_write_key_value(i, DATA_AREA_1, PLAIN_TEXT, &tx_buffer[0], 32);
            if(ret != G3_OK)
              return ret;
            certificate_data_sector_alloc++;
        }
        
        //--- Set TLS Profile (Client) ---------------------------------------------------
	memset(keyusage, 0x11, 1);                                      //ecc client privkey
	memset(keytype, 0x30, 1);                                       //ecc secp256r1 private
	memset(keystate, 0x00, 1);                                      //reserved
        priInfo[0]= 0x00;                       
        priInfo[1]= 0x20;                                               //prvkey length 32byte
        priInfo[2]= G3_CLIENT_CERT_PRIVKEY_KEYSECTOR;                                               //prvkey sector : G3_CLIENT_CERT_PRIVKEY_KEYSECTOR(114)
        priInfo[3]= G3_CLIENT_CERT_PRIVKEY_KEYSECTOR;
        certInfo[0] = ((uint8_t *)(&cert_size))[1];                     //certification length 2byte  
        certInfo[1] = ((uint8_t *)(&cert_size))[0];
        certInfo[2] = cert_offset;                                      //cert start sector num         (0)
        certInfo[3] = (uint8_t ) (certificate_data_sector_alloc-1);         //cert end sector num
        cert_offset = certificate_data_sector_alloc;                
        ret = set_tls_profile(CLIENT, 5, NULL,0,keyusage, keystate,keytype, "CLIENT CERT PEM", priInfo, certInfo, &prov_flag);
	if(ret !=0 )
        {
          printf("write tls Client Cert profile information :failed\r\n");
        }
        
        
        
        //--- Certificate Write (Root CA) -------------------------------------------------------------------
        cert_size = strlen(tlsATS3_ROOT_CERTIFICATE_PEM) + 1;
        for(int i=0; i< ((cert_size-1)/32)+1; i++)
        {
            memset(tx_buffer, 0x00, sizeof(tx_buffer));
            if((i+1)*32 > cert_size)
              size = cert_size - 32*i;
            else
              size = 32;
            
            memcpy(tx_buffer, tlsATS3_ROOT_CERTIFICATE_PEM +32*i, size);
            ret = g3api_write_key_value(cert_offset+i, DATA_AREA_1, PLAIN_TEXT, &tx_buffer[0], 32);
            if(ret != G3_OK)
              return ret;
            certificate_data_sector_alloc++;
        }
        
        //--- Set TLS Profile (Root CA) ---------------------------------------------------
	memset(keyusage, 0x01, 1);                                      //ecc CA privkey
	memset(keytype, 0x00, 1);                                       //key type : none
	memset(keystate, 0x00, 1);                                      //reserved
        memset(priInfo, 0x00, 4);                                       //prvkey : none
	certInfo[0] = ((uint8_t *)(&cert_size))[1];                     //certification length 2byte       
        certInfo[1] = ((uint8_t *)(&cert_size))[0];                      
        certInfo[2] = cert_offset;                                          //cert start sector num
        certInfo[3] = (uint8_t ) (certificate_data_sector_alloc-1);         //cert end sector num
        cert_offset = certificate_data_sector_alloc;
        ret = set_tls_profile(CA, 6, NULL,0,keyusage, keystate,keytype, "CA_CERT_PEM", priInfo, certInfo, &prov_flag);
	if(ret !=0 )
        {
          printf("write tls CA Cert profile information :failed\r\n");
        }

#if 0
        for(int i=0; i<certificate_data_sector_alloc; i++)
        {
            g3api_read_key_value(i, DATA_AREA_1, PLAIN_TEXT, NULL, 0, &recv_key_information, sizeof(ST_KEY_VALUE));
        }  
#endif        

        
 

        return ret;
}



void g3_cert_init()
{
#ifdef ICTK_G3_I2C_DMA
    if(G3_OK != g3p_init())
      return;
#else
    _i2c_init();
#endif    
#ifdef G3_SEMAPHORE
    g3_mutex_new();
#endif    
    g3api_set_user_send_recv_pf(g3_send_recv_, NULL);
    
    if(G3_OK != g3p_wakeup(80,10000))
      return;
    
    if(G3_OK != tls_setup())
      return;
    
    return;
}



#endif