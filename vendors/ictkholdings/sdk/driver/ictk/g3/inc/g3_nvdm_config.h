/* Copyright Statement:
 *  2019 -09-10 
 *  ZN tehnologies 
 *  G3 related parameters will be stored 
 *  amazon info added to amazon group 
 * 
 * @file g3_nvdm_config.h
 *
 */

#ifndef __G3_NVDM_CONFIG_H__
#define __G3_NVDM_CONFIG_H__


#include <stdint.h>
#include "mbedtls/ssl.h"
#include "aws_iot_shadow_interface.h"
#include "aws_iot_config.h"



#define NVDM_EP_LEN             MBEDTLS_SSL_MAX_HOST_NAME_LEN/// = 255 
#define NVDM_TN_LEN             MAX_SIZE_OF_THING_NAME/// = 20
#define NVDM_CID_LEN            MAX_SIZE_OF_UNIQUE_CLIENT_ID_BYTES/// = 80
  /* https://docs.aws.amazon.com/ko_kr/iot/latest/developerguide/device-shadow-document.html#client-token
    Client Token <= 64 Byte
  */


#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
  uint8_t   epoint[NVDM_EP_LEN+1];
  uint8_t   tname[NVDM_TN_LEN+1];
  uint8_t   cid[NVDM_CID_LEN+1];
  uint16_t  portnum;
  uint8_t   ac;  

} g3_cfg_t;


int32_t g3_config_init(g3_cfg_t *g3_config);

#ifdef __cplusplus
}
#endif


#endif


