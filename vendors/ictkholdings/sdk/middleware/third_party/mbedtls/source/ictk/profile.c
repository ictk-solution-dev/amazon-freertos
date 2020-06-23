#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#ifdef ICTK_TLS
#include "g3_api.h"
#endif
#include "mbedtls/x509_crt.h"
#include "mbedtls/oid.h"
#include "ictk/profile.h"
#include "mbedtls/platform.h"
#ifdef G3_PKCS11
#include "g3_pkcs11.h"
#endif
#ifdef __cplusplus
extern "C" {
#endif

//function to convert string to byte array
int /*void*/ string2ByteArray(char* input, uint8_t* output)
{
    int loop;
    int i;
    
    loop = 0;
    i = 0;
    
    while(input[loop] != '\0')//changed by ICTK
    {
        output[i++] = input[loop++];
    }
	return i;
}

void byteArray2String(uint8_t* input, char* output)
{
    int loop;
    int i;
    
    loop = 0;
    i = 0;
    
    while(input[loop] != '\0')
    {
        output[i++] = input[loop++];
    }
}

int set_tls_header_profile(char* profDesc, uint8_t* defCount, uint8_t* whiteListLoc, uint8_t* whiteListStIndex){
	int ret = 0;
	uint8_t b_profDesc[64]= {0,};
	ST_KEY_VALUE _profDesc;
	ST_KEY_VALUE _defCount;
	ST_KEY_VALUE _whiteListLoc;
	ST_KEY_VALUE _whiteListStIndex;
	mbedtls_printf("\n  . set tls header profile...");
	//write profile description
	string2ByteArray(profDesc,b_profDesc);

	//write profile description
	for(int i = 0 ; i < 2 ; i++){
		memset(&_profDesc.key_value[0], 0x00, 32);
		memcpy(&_profDesc.key_value[0], &b_profDesc[i*32], 32);
		ret = g3api_write_key_value(i, DATA_AREA_0, PLAIN_TEXT, &_profDesc, sizeof(_profDesc));
	}
	mbedtls_printf("\n  . profile description...");
	for(int i = 0 ; i < 64 ; i++){
		mbedtls_printf("%02X",_profDesc.key_value[i]);
	}
	//write definition count
	memset(&_defCount.key_value[0], 0x00, 32);
	memcpy(&_defCount.key_value[0], &defCount[0], sizeof(defCount));
	ret = g3api_write_key_value(2, DATA_AREA_0, PLAIN_TEXT, &_defCount, sizeof(_defCount));
	mbedtls_printf("\n  . definition count...");
	for(int i = 0 ; i < 32 ; i++){
		mbedtls_printf("%02X",_defCount.key_value[i]);
	}
	//white list location
	memset(&_whiteListLoc.key_value[0], 0x00, 32);
	memcpy(&_whiteListLoc.key_value[0], &whiteListLoc[0], sizeof(whiteListLoc));
	ret = g3api_write_key_value(3, DATA_AREA_0, PLAIN_TEXT, &_whiteListLoc, sizeof(_whiteListLoc));
	mbedtls_printf("\n  . white list location...");
	for(int i = 0 ; i < 32 ; i++){
		mbedtls_printf("%02X",_whiteListLoc.key_value[i]);
	}
	//white list start index
	memset(&_whiteListStIndex.key_value[0], 0x00, 32);
	memcpy(&_whiteListStIndex.key_value[0], &whiteListStIndex[0], sizeof(whiteListStIndex));
	ret = g3api_write_key_value(4, DATA_AREA_0, PLAIN_TEXT, &_whiteListStIndex, sizeof(_whiteListStIndex));
	mbedtls_printf("\n  . white list start index...");
	for(int i = 0 ; i < 32 ; i++){
		mbedtls_printf("%02X",_whiteListStIndex.key_value[i]);
	}
	return ret;
}

int get_tls_header_profile(char* profDesc, uint8_t* defCount, uint8_t* whiteListLoc, uint8_t* whiteListStIndex){
	int ret = 0;  
	ST_KEY_VALUE _profDesc;
	ST_KEY_VALUE _defCount;
	ST_KEY_VALUE _whiteListLoc;
	ST_KEY_VALUE _whiteListStIndex;

	uint8_t b_profDesc[64]= '\0';	

	for(int i = 0 ; i < 2 ; i++){
		ret = g3api_read_key_value(i, DATA_AREA_0, PLAIN_TEXT, NULL, 0, &_profDesc, sizeof(_profDesc));
		memcpy(&b_profDesc[i*32],&_profDesc.key_value[0], 32);
	}
	byteArray2String(b_profDesc ,profDesc);

	//write definition count
	ret = g3api_read_key_value(2, DATA_AREA_0, PLAIN_TEXT, NULL, 0, &_defCount, sizeof(_defCount));
	memcpy(&defCount[0],&(_defCount.key_value[0]),sizeof(ST_KEY_VALUE));

	//white list location
	ret = g3api_read_key_value(3, DATA_AREA_0, PLAIN_TEXT, NULL, 0, &_whiteListLoc, sizeof(_whiteListLoc));
	memcpy(&whiteListLoc[0],&(_whiteListLoc.key_value[0]),sizeof(ST_KEY_VALUE));

	//white list start index
	ret = g3api_read_key_value(4, DATA_AREA_0, PLAIN_TEXT, NULL, 0, &_whiteListStIndex, sizeof(_whiteListStIndex));
	memcpy(&whiteListStIndex[0],&(_whiteListStIndex.key_value[0]),sizeof(ST_KEY_VALUE));

	/*mbedtls_printf("\n  . get tls header profile...");
	mbedtls_printf("\n  . profile description...");
	mbedtls_printf("%s",profDesc);

	mbedtls_printf("\n  . definition count...");
	mbedtls_printf("%02X",defCount[0]);

	mbedtls_printf("\n  . white list location...");
	mbedtls_printf("%02X",whiteListLoc[0]);

	mbedtls_printf("\n  . white list start index...");
	mbedtls_printf("%02X",whiteListStIndex[0]);
	mbedtls_printf("\n");*/
	return ret;
}


int set_tls_profile(KEYUSAGE keyusagemode, uint8_t sectornum, uint8_t* key_information, uint8_t len,
uint8_t* keyusage, uint8_t* keystate, uint8_t* keytype, char* caseDesc, uint8_t* pri_info,uint8_t* certinfo, uint8_t* prov_flag){
	int ret = 0;
	char ascii_str[] = "Hello world!";
    const int len_ = strlen(ascii_str);
    uint8_t i_arr[64]= {0,};	
	char o_arr[64] ='\0';
    int i;
	uint8_t tls_key_information[32]= {0,};	
	//uint8_t b_caseDesc[21]= {0,};
	uint8_t b_caseDesc[20]= {0,};
	ST_KEY_VALUE _tls_key_information;
	mbedtls_printf("\n	. set profile...");

	string2ByteArray(caseDesc,b_caseDesc);
	//total size : 32 byte
	memcpy(&_tls_key_information.key_value[0],&keyusage[0], 1);	//key usage
	memcpy(&_tls_key_information.key_value[1],&keystate[0], 1); 	//key state
	memcpy(&_tls_key_information.key_value[2],&keytype[0], 1); 	//key type
	//memcpy(&_tls_key_information.key_value[3],&b_caseDesc[0], 21); //case description
	memcpy(&_tls_key_information.key_value[3],&b_caseDesc[0], 20); //case description
	memcpy(&_tls_key_information.key_value[23],&prov_flag[0], 1); //case description
	memcpy(&_tls_key_information.key_value[24],&pri_info[0], 4);	//private information
	memcpy(&_tls_key_information.key_value[28],&certinfo[0], 4);	//certificate information
	_tls_key_information.key_value[23] = *prov_flag; 
#if 0
	mbedtls_printf("\n  . key information...");
	for(int i = 0 ; i < 32 ; i++){
		mbedtls_printf("%02X",_tls_key_information.key_value[i]);
	}
	mbedtls_printf("\r\n");
#endif
	ret = g3api_write_key_value(sectornum, DATA_AREA_0, PLAIN_TEXT, &_tls_key_information, sizeof(_tls_key_information));
	return ret;
}

int get_tls_profile(KEYUSAGE keyusagemode, uint8_t sectornum, uint8_t* key_information, uint8_t len){
	int ret = 0;
	ST_KEY_VALUE recv_key_information;
	uint8_t b_caseDesc[21]= '\0';
	char c_caseDesc[21] = '\0';;
	uint8_t priInfo[4]= {0,};
	uint8_t certInfo[4]= {0,};
	uint8_t _key_information[32];
	ret = g3api_read_key_value(sectornum, DATA_AREA_0, PLAIN_TEXT, NULL, 0, &recv_key_information,  sizeof(ST_KEY_VALUE));
	memcpy(&_key_information[0],&(recv_key_information.key_value[0]),sizeof(ST_KEY_VALUE));
	memcpy(&b_caseDesc[0],&_key_information[3], 21 );
	byteArray2String(b_caseDesc ,c_caseDesc);
#if 0
	//mbedtls_printf("\n  . key information...");
	//for(int i = 0 ; i < 32 ; i++){
	//	mbedtls_printf("%02X",_key_information[i]);
	//}
	//mbedtls_printf("\r\n");

	mbedtls_printf("\n  . get tls profile...");

	mbedtls_printf("\n  . key usage...");
	mbedtls_printf("%02X",_key_information[0]);

	mbedtls_printf("\n  . key state...");
	mbedtls_printf("%02X",_key_information[1]);

	mbedtls_printf("\n  . key type...");
	mbedtls_printf("%02X",_key_information[2]);

	mbedtls_printf("\n  . case description...");
	mbedtls_printf("%s",c_caseDesc);

	mbedtls_printf("\n  . get private information...");
	
#endif
        memcpy(&priInfo[0],&_key_information[24], 4 );
	/*
        for(int i = 0 ; i < 4 ; i++)
		mbedtls_printf("%02X",priInfo[i]);

	mbedtls_printf("\n  . get certificate information...");
*/
	memcpy(&certInfo[0],&_key_information[28], 4 );
	//for(int i = 0 ; i < 4 ; i++)
		//mbedtls_printf("%02X",certInfo[i]);
	memcpy(&key_information[0],&_key_information[0],sizeof(_key_information));
        
	return ret;
}

int set_tls_provisioning_profile(KEYUSAGE keyusagemode, uint8_t sectornum, uint8_t* provisioning){
	int ret = 0;
	char ascii_str[] = "Hello world!";
    const int len_ = strlen(ascii_str);
    uint8_t i_arr[64]= {0,};	
	char o_arr[64] ='\0';
    int i;
	uint8_t tls_key_information[32]= {0,};	
	uint8_t b_caseDesc[21]= {0,};
	ST_KEY_VALUE _tls_key_information;
	mbedtls_printf("\n	. set_tls_provisioning_profile...");

    ret = get_tls_profile(keyusagemode, sectornum, tls_key_information,sizeof(tls_key_information));

	//memcpy(&tls_key_information[23],&provisioning[0], 1);	//private information
	tls_key_information[23] = *provisioning ;
	mbedtls_printf("\n  . key information...");
    mbedtls_printf("%02X",tls_key_information[23]);

	mbedtls_printf("\r\n");
	
	memcpy(&(_tls_key_information.key_value[0]),&tls_key_information[0],32);
	ret = g3api_write_key_value(sectornum, DATA_AREA_0, PLAIN_TEXT, &_tls_key_information, sizeof(_tls_key_information));
	return ret;
}

int get_tls_provisioning_profile(KEYUSAGE keyusagemode, uint8_t sectornum, uint8_t* provisioning){
	ST_KEY_VALUE recv_key_information;
	uint8_t _key_information[32];
	uint8_t m_provisioning[1];
	int ret = -1;
	ret = g3api_read_key_value(sectornum, DATA_AREA_0, PLAIN_TEXT, NULL, 0, &recv_key_information,  sizeof(ST_KEY_VALUE));
	memcpy(&_key_information[0],&(recv_key_information.key_value[0]),sizeof(ST_KEY_VALUE));
	//memcpy(provisioning[0],&(recv_key_information.key_value[23]),sizeof(ST_KEY_VALUE));
    provisioning[0] = _key_information[23];
  
	mbedtls_printf("\n  . get_tls_provisioning_profile type[%d]...",sectornum);
    mbedtls_printf("%02X",_key_information[23]);
	return ret;
}

int set_tls_whitelist(uint8_t startWhitelistIndex, uint8_t index_size, uint8_t* cert, size_t certlen, char* _cn, int _cn_len, int withCN){
	int ret = 0;
	mbedtls_x509_crt clicert;
	char cn[32] = '\0';
	size_t cn_len;
	uint8_t b_cn[32] = {0,};
	ST_KEY_VALUE i_whitelist;
	ST_KEY_VALUE o_whitelist;
	char seperator[1] =",";
	int findWhiteList = 0;
	int updateWhiteList = 0 ;
	uint8_t default_check[32] = {0,}; 
	uint8_t initstart = startWhitelistIndex ;
	uint8_t index = startWhitelistIndex ;
	int i , j ;
	int k;
	uint8_t temp[32] = {0,}; 
	mbedtls_printf("\n  . set tls whitelist...");

	//memset(&i_whitelist.key_value[0], 0x00, 32);
	//ret = g3api_write_key_value(index, DATA_AREA_1, PLAIN_TEXT, &i_whitelist, sizeof(i_whitelist));
	if(withCN == 0){
		mbedtls_x509_crt_init(&clicert);
		ret = mbedtls_x509_crt_parse(&clicert, (const unsigned char *)cert, certlen);

	   	x509_crt_parse_cn(&clicert, cn, &cn_len);
		strncat(cn,seperator,1);	
		cn_len += 1;
		mbedtls_printf("%s",cn);
		
	    //strcpy(cn, "www.ictk.com");
		//cn_len = strlen(cn);

		mbedtls_x509_crt_free(&clicert);
	}else{
		strncpy(cn, _cn, _cn_len);
		strncat(cn,seperator,1);	
		cn_len = _cn_len+ 1;
	}
	string2ByteArray(cn,b_cn);
	
	memset(&i_whitelist.key_value[0], 0x00, 32);
	memcpy(&i_whitelist.key_value[0], b_cn, cn_len);

	for(int i = 0 ; i < 32 ; i++)
		mbedtls_printf("%02X",b_cn[i]);

	//Check update or not
	for(j = 0 ; j < index_size ; j++){
		ret = g3api_read_key_value(index + j, DATA_AREA_0, PLAIN_TEXT, NULL, 0, &o_whitelist,  sizeof(ST_KEY_VALUE));

		for(k = 0 ; k < 32 ; k++){
		if(o_whitelist.key_value[k] == 0x2C){
			memcpy(&temp[0], &o_whitelist.key_value[(k + 1)-cn_len], cn_len);
			if(/*k-cn_len > 0 && */memcmp(b_cn,&o_whitelist.key_value[(k + 1)-cn_len],cn_len) == 0){
				goto end;
				break;
			}
			}
		}

	}
	for( j = 0 ; j < index_size ; j++){
		ret = g3api_read_key_value(index + j, DATA_AREA_0, PLAIN_TEXT, NULL, 0, &o_whitelist,  sizeof(ST_KEY_VALUE));
		if(memcmp(default_check, &o_whitelist.key_value[0] , 32) == 0){
			ret = g3api_write_key_value(index + j, DATA_AREA_0, PLAIN_TEXT, &i_whitelist, sizeof(i_whitelist));
            goto end;
		}else{
			for(int k = 31 ; k >= 0 ; k--){
				if(o_whitelist.key_value[k] == 0x2C){
					if( k + cn_len + 1 < 32){
						memset(&i_whitelist.key_value[0], 0x00, 32);
						memcpy(&i_whitelist.key_value[0], &o_whitelist.key_value[0], k+1);
						memcpy(&i_whitelist.key_value[k+1], b_cn, cn_len);
						ret = g3api_write_key_value(index + j, DATA_AREA_0, PLAIN_TEXT, &i_whitelist, sizeof(i_whitelist));
					}else{
						ret = g3api_write_key_value(index + j + 1, DATA_AREA_0, PLAIN_TEXT, &i_whitelist, sizeof(i_whitelist));
					}
					goto end;
				}
			}
		}
	}
	end:
	return ret;
}
int get_tls_whitelist(uint8_t startWhitelistIndex, uint8_t index_size, uint8_t* whitelist, size_t whitelistlen){
	int ret = 0;
	ST_KEY_VALUE whitelist_info;
	uint8_t b_whitelist[32] = {0,};;
	char c_whitelist[32] = '\0';;
	for(int i = 0 ; i < index_size ; i++){
		memset(b_whitelist, 0x00, 32);
		memset(c_whitelist, 0x00, 32);
		ret = g3api_read_key_value(startWhitelistIndex + i, DATA_AREA_0, PLAIN_TEXT, NULL, 0, &whitelist_info,  sizeof(ST_KEY_VALUE));
		memcpy(&b_whitelist[0],&(whitelist_info.key_value[0]),sizeof(ST_KEY_VALUE));
		byteArray2String(b_whitelist ,c_whitelist);	
		if(memcmp(b_whitelist,"\x0\x0\x0\x0" ,3) != 0){
			mbedtls_printf("\n  . get tls whitelist...");
			mbedtls_printf("%s",c_whitelist);
		}
	}
}

int get_tls_whitelist2(uint8_t index, uint8_t* whitelist, size_t whitelistlen){
	int ret = 0;
	ST_KEY_VALUE whitelist_info;
	uint8_t b_whitelist[32] = {0,};;
	char c_whitelist[32] = '\0';
	memset(b_whitelist, 0x00, 32);
	memset(c_whitelist, 0x00, 32);
	ret = g3api_read_key_value(index, DATA_AREA_0, PLAIN_TEXT, NULL, 0, &whitelist_info,  sizeof(ST_KEY_VALUE));
	memcpy(&whitelist[0],&(whitelist_info.key_value[0]),sizeof(ST_KEY_VALUE));
	byteArray2String(whitelist ,c_whitelist);	
	if(memcmp(whitelist,"\x0\x0\x0\x0" ,3) != 0){
		mbedtls_printf("\n  . get tls whitelist...");
		mbedtls_printf("%s",c_whitelist);
	}
	return ret;
}


int set_tls_keystate(KEYUSAGE keyusagemode, uint8_t sectornum, uint8_t keystate){
	int ret = 0;
	ST_KEY_VALUE recv_key_information;
	uint8_t priInfo[4]= {0,};
	uint8_t certInfo[4]= {0,};
	uint8_t _key_information[32];
	ret = g3api_read_key_value(sectornum, DATA_AREA_0, PLAIN_TEXT, NULL, 0, &recv_key_information,  sizeof(ST_KEY_VALUE));
	memcpy(&_key_information[0],&(recv_key_information.key_value[0]),sizeof(ST_KEY_VALUE));
	_key_information[1] = keystate;

	memcpy(&(recv_key_information.key_value[0]), &_key_information[0],sizeof(ST_KEY_VALUE));
	ret = g3api_write_key_value(sectornum, DATA_AREA_0, PLAIN_TEXT, &recv_key_information, sizeof(ST_KEY_VALUE));

	return ret;
}


uint8_t get_tls_keystate(KEYUSAGE keyusagemode, uint8_t sectornum){
	int ret = 0;
	ST_KEY_VALUE recv_key_information;
	uint8_t priInfo[4]= {0,};
	uint8_t certInfo[4]= {0,};
	uint8_t _key_information[32];
	ret = g3api_read_key_value(sectornum, DATA_AREA_0, PLAIN_TEXT, NULL, 0, &recv_key_information,  sizeof(ST_KEY_VALUE));
	memcpy(&_key_information[0],&(recv_key_information.key_value[0]),sizeof(ST_KEY_VALUE));

	return _key_information[1];
}


int init_tls_whitelist(uint8_t startWhitelistIndex, uint8_t index_size){
	int ret = 0;
	int i ;
	ST_KEY_VALUE defaultvalue;
	memset(&defaultvalue.key_value[0], 0x00, 32);
	for(i = 0 ; i < index_size ; i++)
	ret = g3api_write_key_value(startWhitelistIndex + i, DATA_AREA_0, PLAIN_TEXT, &defaultvalue, sizeof(defaultvalue));
	return ret;
}

int get_tls_cert_end_sector(KEYUSAGE keyusagemode, uint8_t sectornum, uint8_t* end_sector){
	ST_KEY_VALUE recv_key_information;
	uint8_t _key_information[32];
	uint8_t tls_key_information[32]= {0,};	
	int ret = -1;
    ret = get_tls_profile(keyusagemode, sectornum, tls_key_information,sizeof(tls_key_information));
	*end_sector = tls_key_information[31];
        return ret;
}

static int x509_crt_get_cn( const mbedtls_x509_buf *name,
							  char *cn, size_t* cn_len )
{
  int ret = 0;
  char cn_[32] = '\0';
  *cn_len = name->len;
  strncpy(cn,name->p,*cn_len);
  return ret;
}

static void x509_crt_parse_cn( const mbedtls_x509_crt *crt, char *cn , size_t* cn_len){
    const mbedtls_x509_name *name;
	size_t cn_len_;
	char _cn[32] = '\0';

    for( name = &crt->subject; name != NULL; name = name->next )
    {
        if( MBEDTLS_OID_CMP( MBEDTLS_OID_AT_CN, &name->oid ) == 0)
        {
        	x509_crt_get_cn( &name->val, _cn, &cn_len_ );
            strncpy(cn,_cn,cn_len_);
            *cn_len = cn_len_;
            break;
        }
    }

}

int get_cert_from_profile(KEYUSAGE keyusagemode, uint8_t* cert, int* certlen)
{
    int ret = -1;
    uint8_t profile[32];
    ST_KEY_VALUE recv_key_information;
    uint8_t sectornum = 0;
    int cert_len = 0;
    uint8_t *temp_cert = pvPortMalloc(*certlen);
    int templen = *certlen;
    *certlen = 0;
    switch(keyusagemode)
    {
      case CA:
        sectornum = 6;
        break;
      case CLIENT:
        sectornum = 5;
        break;       
      case SERVER:
        sectornum = 7;
        break;
#ifdef G3_PKCS11
      case PKCS_CERT:
        sectornum = G3_PKCS11_CERT_PROFILE_SECTOR;
        break;
#endif
      default:
        vPortFree(temp_cert);
        return -1;
    }
    ret = get_tls_profile(keyusagemode, sectornum, profile, 32);
    //ret = g3api_read_key_value(sectornum, DATA_AREA_0, PLAIN_TEXT, NULL, 0, profile,  sizeof(ST_KEY_VALUE));
    
    if( 0 != ret)
    {
      vPortFree(temp_cert);
      return ret;
    }
    
    if((((int)(profile[31] - profile[30]))*32) > templen)
    {
      //printf("[ICTK]get_cert_from_profile - buffer is too short.\m");
      vPortFree(temp_cert);
      return -1;
    }

    cert_len = (profile[28]<<8) + (profile[29]);
    
    for(int i =0; i<(profile[31] - profile[30] + 1); i++ )
    {
      	ret = g3api_read_key_value(profile[30] + i, DATA_AREA_1, PLAIN_TEXT, NULL, 0, &recv_key_information,  sizeof(ST_KEY_VALUE));
        if(ret != 0)
        {
          vPortFree(temp_cert);
          return ret;
        }
        memcpy(temp_cert+32*i, &recv_key_information.key_value, 32);
    }
    memcpy(cert, temp_cert, cert_len);
    *certlen = cert_len;
    vPortFree(temp_cert);
    return 0;
}


#ifdef __cplusplus
}
#endif
