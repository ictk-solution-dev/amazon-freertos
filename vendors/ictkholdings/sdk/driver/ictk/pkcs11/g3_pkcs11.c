/*
* FreeRTOS
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * http://aws.amazon.com/freertos
 * http://www.FreeRTOS.org
 */

/**
 * @file fake_PKCS11.c
 * @brief This port is not using pkcs11, however it is used in the test to retrive code signer.
 */

 /* FreeRTOS includes. */
#include "FreeRTOS.h"
#include "g3_pkcs11.h"
#include "iot_pkcs11.h"
#include "g3_define.h"
#include "ictk/profile.h"   


        
#ifdef G3_PKCS11   

extern int certificate_data_sector_alloc;
static char *strstr_custom(const char *str1, const char *str2);
static int profile_sector_from_filename(char *filename);

static int profile_sector_from_filename(char *filename)            //You need profile_sector limitaion (ex 8, 9, 10)
{
  int profile_sector = 0;
  uint8_t key_profile[32];
  char* findfilename = NULL;
  
  for(profile_sector =G3_PKCS11_PRV_PROFILE_SECTOR; profile_sector<G3_PKCS11_CERT_PROFILE_SECTOR+1; profile_sector++)   //pkcs sector range
  {
     if(0 != get_tls_profile(0, profile_sector, key_profile, 32) )  //warning keyusage == 0
        return -1;
     
     findfilename = strstr_custom((char* )key_profile, filename);
     
     if( findfilename != NULL )
       return profile_sector;
  }
  
  return -1;
}

static char *strstr_custom(const char *str1, const char *str2) {
  char *cp = (char *)str1;
  char *s1, *s2;
  volatile int i = 0;
  if (!*str2) return (char *)str1;
  while (i<32) {
    s1 = cp;
    s2 = (char *)str2;
    while (*s1 && *s2 && !(*s1 - *s2)) s1++, s2++;
    if (!*s2) return cp;
    cp++;
    i++;
  }
  return NULL;
}

static g3_pkcs11_data_type_t type_from_profile(uint8_t *profile)
{
  if( profile[28] != 0 || profile[29] != 0 )                       //certificate
    return G3_ECC_CERT;
  else if( profile[25] == 0x20 )                            //key type prvkey
    return G3_ECC_PRIV_KEY;
  else if( profile[25] == 0x40 )                            //key type pubkey
    return G3_ECC_PUB_KEY;
  else
    return G3_ZERO;
}


void G3_pkcs11_init()
{
#if G3_PKCS11_PRV_KEY_SECTOR != 104
#error ecc prv&pub key sectors error
#endif
     int size = 0;
     uint8_t tx_buffer[256];
     int ret = -1;
    //--- Key Area Setup (Client Certificate private key) -------------------------------------------------------------------
    memset(tx_buffer, 0x00, sizeof(tx_buffer));
    size = set_buffer_from_hexstr(tx_buffer,(const char*)"2E540000000000003E5400000000000000540000000000000054000000000000");
    ret = g3api_write_key_value(4+(G3_PKCS11_PRV_KEY_SECTOR/4), SETUP_AREA, PLAIN_TEXT, &tx_buffer[0], size);
    if(ret != G3_OK)
    {
      printf("G3_pkcs11_init failed\n");
    }

    for(int i= G3_PKCS11_PRV_PROFILE_SECTOR; i <= G3_PKCS11_CERT_PROFILE_SECTOR; i++)
    {
      memset(tx_buffer, 0x00, sizeof(tx_buffer));
      size = set_buffer_from_hexstr(tx_buffer,(const char*)"0000000000000000000000000000000000000000000000000000000000000000");
      ret = g3api_write_key_value(i, DATA_AREA_0, PLAIN_TEXT, &tx_buffer[0], 32);
      if(ret != G3_OK)
      {
        printf("G3_pkcs11_init failed\n");
      }
    }
    
    
    return;
}
   



int pkcs11_data_write(char* filename, uint8_t* data, uint32_t datalen, g3_pkcs11_data_type_t type)
{
    int ret = -1;
    uint8_t tx_buffer[1024];
    uint32_t cert_size = 0;
    int size = 0;
    uint8_t profile[32];
    int profile_sector = -1;
#if 1   //profile
    uint8_t keyusage[1] = {0,};
    uint8_t keytype[1] = {0,};
    uint8_t keystate[1] = {0,};
    uint8_t priInfo[4] = {0,};
    uint8_t certInfo[4] = {0,};
    uint8_t cert_offset = 0x00;
    uint8_t prov_flag = 0x99;
#endif
    
    if(datalen>1024)
      return -1;
    if(strlen(filename)> G3_PROFILE_STRING_MAX)
      return -1;
    
   
/*                                                              //Overwrite
    profile_sector = profile_sector_from_filename(filename);
       
    if(profile_sector == -1)
      return -1;
    else
    {
      if(0 != get_tls_profile(0, profile_sector, key_profile, 32) )  //warning keyusage == 0
        return -1;                                                   
    }
    type = type_from_profile(key_profile);
*/
    
    switch(type)
    {
        case G3_ECC_PRIV_KEY:
        memset(keyusage, 0x11, 1);                                      //ecc client privkey
	memset(keytype, 0x30, 1);                                       //ecc secp256r1 private
	memset(keystate, 0x00, 1);                                      //reserved
        priInfo[0]= 0x00;                       
        priInfo[1]= 0x20;                                               //prvkey length 32byte
        priInfo[2]= G3_PKCS11_PRV_KEY_SECTOR;                           //prvkey sector : G3_PKCS11_PRV_KEY_SECTOR(104)
        priInfo[3]= G3_PKCS11_PRV_KEY_SECTOR;
        memset(certInfo, 0x00, 4);
        ret = set_tls_profile(PKCS_PRV, G3_PKCS11_PRV_PROFILE_SECTOR, NULL,0,keyusage, keystate,keytype, filename, priInfo, certInfo, &prov_flag);
	if(ret !=0 )
        {
            printf("pkcs11_data_write : set_ecc_prv_profile failed\r\n");
            return -1;
        }
        else
        {
            memset(tx_buffer, 0x00, sizeof(tx_buffer));
            memcpy(tx_buffer, data+7, 32);
            ret = g3api_write_key_value(G3_PKCS11_PRV_KEY_SECTOR, KEY_AREA, PLAIN_TEXT, &tx_buffer[0], 32);
        }
        
        if(ret != 0)
        {
            printf("pkcs11_data_write : set_ecc_prvkey failed\r\n");
            return -1;
        }
        //write pubkey
        //g3api_get_public_key(pxObjectValue[26], KEY_SECTOR, ( uint8_t * ) pxTemplate[ iAttrib ].pValue+3, sizeof(ST_ECC_PUBLIC)); //pubkey from prvkey profile ( prvkey sector : profile[26])
        break;
        
      case G3_ECC_PUB_KEY:
          mbedtls_pk_context ctx;
          mbedtls_pk_init(&ctx);
          ret = mbedtls_pk_parse_public_key( &ctx, data, datalen );
          if(ret != 0 )
          {
              mbedtls_pk_free(&ctx);
              return -1;
          }
          
          mbedtls_ecp_keypair *pxKeyPair = ( mbedtls_ecp_keypair * ) ctx.pk_ctx;
          datalen = 67;
          ret = mbedtls_ecp_tls_write_point( &pxKeyPair->grp, &pxKeyPair->Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &datalen, tx_buffer, 66);
          mbedtls_pk_free(&ctx); 
          if(ret != 0 )
          {
              return -1;
          }
          
          memset(keyusage, 0x11, 1);                                      //ecc client privkey
          memset(keytype, 0x90, 1);                                       //ecc secp256r1 public key
          memset(keystate, 0x00, 1);                                      //reserved
          priInfo[0]= 0x00;                       
          priInfo[1]= 0x40;                                               //pubkey length 64byte
          priInfo[2]= G3_PKCS11_PUB_KEY_SECTOR;                           //pubkey sector : G3_PKCS11_PRV_KEY_SECTOR(104)
          priInfo[3]= G3_PKCS11_PUB_KEY_SECTOR+1;
          memset(certInfo, 0x00, 4);
          ret = set_tls_profile(PKCS_PUB, G3_PKCS11_PUB_PROFILE_SECTOR, NULL,0,keyusage, keystate,keytype, filename, priInfo, certInfo, &prov_flag);
          if(ret !=0 )
          {
              printf("pkcs11_data_write : set_ecc_pub_profile failed\r\n");
              return -1;
          }
          
          for(int i =0; i<2; i++)                                          //write pubkey
          {
              ret = g3api_write_key_value(G3_PKCS11_PUB_KEY_SECTOR+i, KEY_AREA, PLAIN_TEXT, &tx_buffer[2+32*i], 32);
              if(ret != G3_OK)
              {
                  return -1;
              }
          }
          break;
        
        
      case G3_ECC_CERT:
        cert_size = datalen;
        cert_offset = certificate_data_sector_alloc;
        for(int i=0; i< ((cert_size-1)/32)+1; i++)
        {
            memset(tx_buffer, 0x00, sizeof(tx_buffer));
            if((i+1)*32 > cert_size)
                size = cert_size - 32*i;
            else
                size = 32;
            
            memcpy(tx_buffer, data +32*i, size);
            ret = g3api_write_key_value(cert_offset+i, DATA_AREA_1, PLAIN_TEXT, &tx_buffer[0], 32);
            if(ret != G3_OK)
            {
                printf("pkcs11_data_write : write_cert failed\r\n");
                return ret;
            }
            certificate_data_sector_alloc++;
        }
        
        //set profile
        memset(keyusage, 0x11, 1);                                      //ecc client privkey
	memset(keytype, 0x30, 1);                                       //ecc secp256r1 private
	memset(keystate, 0x00, 1);                                      //reserved
        priInfo[0]= 0x00;                       
        priInfo[1]= 0x20;                                               //prvkey length 32byte
        priInfo[2]= G3_PKCS11_PRV_KEY_SECTOR;                           //prvkey sector : G3_PKCS11_PRV_KEY_SECTOR(104)
        priInfo[3]= G3_PKCS11_PRV_KEY_SECTOR;
        certInfo[0] = ((uint8_t *)(&cert_size))[1];                     //certification length 2byte  
        certInfo[1] = ((uint8_t *)(&cert_size))[0];
        certInfo[2] = cert_offset;                                      //cert start sector num         (0)
        certInfo[3] = certificate_data_sector_alloc;                    //cert end sector num        
        ret = set_tls_profile(PKCS_CERT, G3_PKCS11_CERT_PROFILE_SECTOR, NULL,0,keyusage, keystate,keytype, filename, priInfo, certInfo, &prov_flag);
	if(ret !=0 )
        {
            printf("pkcs11_data_write : set_cert_profile failed\r\n");
            return -1;
        }
        break;
        
        case G3_ZERO:
            for(profile_sector = profile_sector_from_filename(filename); profile_sector != -1; )
            {
                if(profile_sector == G3_PKCS11_PRV_PROFILE_SECTOR)
                {
                    memset(tx_buffer, 0x00, sizeof(tx_buffer));
                    size = set_buffer_from_hexstr(tx_buffer,(const char*)"0000000000000000000000000000000000000000000000000000000000000000");
                    ret = g3api_write_key_value(G3_PKCS11_PRV_KEY_SECTOR, KEY_AREA, PLAIN_TEXT, &tx_buffer[0], 32);
                    if(ret != G3_OK)
                    {
                        return -1;
                    }
                }
                else if(profile_sector == G3_PKCS11_PUB_PROFILE_SECTOR)
                {
                    memset(tx_buffer, 0x00, sizeof(tx_buffer));
                    size = set_buffer_from_hexstr(tx_buffer,(const char*)"0000000000000000000000000000000000000000000000000000000000000000");
                    for(int i =0; i<2; i++)
                    {
                        ret = g3api_write_key_value(G3_PKCS11_PUB_KEY_SECTOR+i, KEY_AREA, PLAIN_TEXT, &tx_buffer[0], 32);
                        if(ret != G3_OK)
                        {
                            return -1;
                        }
                    }
                }
                else if(profile_sector == G3_PKCS11_CERT_PROFILE_SECTOR)
                {
                    get_tls_profile(PKCS_PRV, profile_sector, profile, G3_PROFILE_LENGTH);
                    size = profile[31] - profile[30];
                    if(size < 0)
                        return -1;
                    certificate_data_sector_alloc = certificate_data_sector_alloc - size;
                    if(certificate_data_sector_alloc < 0)
                        return -1;
                }
                  
                memset(tx_buffer, 0x00, sizeof(tx_buffer));
                size = set_buffer_from_hexstr(tx_buffer,(const char*)"0000000000000000000000000000000000000000000000000000000000000000");
                ret = g3api_write_key_value(profile_sector, DATA_AREA_0, PLAIN_TEXT, &tx_buffer[0], 32);
                if(ret != G3_OK)
                {
                    return -1;
                }
                profile_sector = profile_sector_from_filename(filename);
              
            }
            break;
          
        default:
            return -1;
    }
    return 0;
}


int pkcs11_data_read(char* filename, uint8_t* data, uint32_t* datalen)  //, g3_pkcs11_data_type_t type)
{
    int ret = -1;
    uint8_t profile[32];
    uint8_t comp[32];
    uint8_t key_profile[32];
    uint32_t cert_size = 0;
    uint8_t cert[1024];
    uint32_t certlen = sizeof(cert);
    int profile_sector = 0;
    g3_pkcs11_data_type_t type;
    char* findfilename = NULL;
    uint32_t temp_datalen = 0;
    memset(profile, 0x00, 32);
    memset(comp, 0x00, 32);
    
    
    temp_datalen = *datalen;
    *datalen = 0;                                                   
    
    if(strlen(filename)> G3_PROFILE_STRING_MAX)
      return -1;
  
    profile_sector = profile_sector_from_filename(filename);

    
    if(profile_sector == -1)
      return -1;
    else
    {
      if(0 != get_tls_profile(0, profile_sector, key_profile, 32) )  //warning keyusage == 0
        return -1;                                                   
    }

    type = type_from_profile(key_profile);
    
    switch(type)
    {
      case G3_ECC_PRIV_KEY:
        get_tls_profile(PKCS_PRV, profile_sector, profile, G3_PROFILE_LENGTH);
        if(memcmp(profile, comp, G3_PROFILE_LENGTH) == 0)
          return -1;
        if(temp_datalen >= certlen)
        {
          memcpy(data, profile, G3_PROFILE_LENGTH);      
          *datalen = G3_PROFILE_LENGTH;
        }
        else
          return -1;

        break;
        
      case G3_ECC_PUB_KEY:
        get_tls_profile(PKCS_PUB, profile_sector, profile, G3_PROFILE_LENGTH);
        if(memcmp(profile, comp, G3_PROFILE_LENGTH) == 0)
          return -1;
        
        ret = g3api_get_public_key(profile[26], KEY_SECTOR, cert, sizeof(ST_ECC_PUBLIC));       //sizeof(ST_ECC_PUBLIC_COMPRESS) compress form
        if(ret != 0)
          return -1;
        if(temp_datalen >= G3_ECC_PUBKEY_LENGTH)
        {
          memcpy(data, cert, G3_ECC_PUBKEY_LENGTH);      
          *datalen = G3_ECC_PUBKEY_LENGTH;
        }
        else
          return -1;

        break;    
        
      case G3_ECC_CERT:
        certlen = sizeof(cert);

        ret = get_cert_from_profile(PKCS_CERT, cert, &certlen);            //warning
        if(ret != 0)
          return -1;
        if(temp_datalen >= certlen)
        {
          memcpy(data, cert, certlen);      
          *datalen = certlen;
        }
        else
          return -1;
        break;
        
      case G3_ZERO:
        get_tls_profile(PKCS_PUB, profile_sector, profile, G3_PROFILE_LENGTH);        //warning PKCS_PUB?
        if(memcmp(profile, comp, G3_PROFILE_LENGTH) != 0)
          return -1;
        break;   

      default:
        return -1;
    }
    return 0;
}

#endif