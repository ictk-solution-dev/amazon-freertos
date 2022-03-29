#ifndef __GLOBAL_H__
#define __GLOBAL_H__

#define INCLUDE_xTaskAbortDelay 1
#define INCLUDE_xTaskGetCurrentTaskHandle 1
#define configSUPPORT_STATIC_ALLOCATION 1
#define configNUM_THREAD_LOCAL_STORAGE_POINTERS 3

#define ZWG3M_VER               "b1911a"


#define PCFG_OS                 2
#define _REENT_SMALL
#define PRODUCT_VERSION         7686
#define MT5932_SINGLE_CONTEXT
#define MTK_ROM_VER             e2
#define MT7686_E2_ENABLE 
#define E2_ROM_7682 
#define MTK_CM4_WIFI_TASK_ENABLE
#define MTK_CM4_N9_SINGLE_IMG
#define MTK_HIF_HEADER_2DW

#define MTK_LWIP_ENABLE
#define MTK_MT7686_ENABLE
#define USE_HAL_DRIVER

#define MTK_NVDM_ENABLE 
#define MTK_WIFI_ROM_ENABLE 
#define MTK_HAL_LOWPOWER_ENABLE 
#define MTK_WIFI_PROFILE_ENABLE
#define DATA_PATH_87
#define MTK_WIFI_REPEATER_ENABLE
#define SUPPORT_MBEDTLS
#define MBEDTLS_CONFIG_FILE     "config-mtk-multiple-ciphersuits.h"



//------------------------------------------------------------------------------
/*              ICTK_DEMO_CERTIFICATE      */
//------------------------------------------------------------------------------
#define ICTK_DEMO_CERTIFICATE

#ifdef ICTK_DEMO_CERTIFICATE
#include "$PROJ_DIR$\..\..\..\..\..\vendors\ictkholdings\boards\ZWG3M\aws_demos\certificate\aws_clientcredential_keys.h"
#endif

//------------------------------------------------------------------------------
/*              ICTK_CONFIG      */
//------------------------------------------------------------------------------
#define ICTK_TLS_FOR_AWSTEST
#define ATCI_CH_TESTLOG_PRINT_FOR_AWSTEST
#define ICTK_TLS                                               
#define ICTK_TLS_PREMASTER_IN_PUF                                 
#undef ICTK_TLS_DEBUG                      

//------------------------------------------------------------------------------
/*              G3_CONFIG      */
//------------------------------------------------------------------------------
//#define ICTK_G3_I2C_DMA
//#define G3_SEMAPHORE
#define G3_PKCS11 
#define G3_MAX_CERT_SIZE                    ( 3000)

//------------------------------------------------------------------------------
/*              TEST_CONFIG      */
//------------------------------------------------------------------------------
//#define MBEDTLS_ENTROPY_NV_SEED			
#define MBEDTLS_ENTROPY_HARDWARE_ALT		
#define MBEDTLS_ENTROPY_C                     

//------------------------------------------------------------------------------
#undef ZNT_MINICLI
//------------------------------------------------------------------------------
#ifdef ZNT_MINICLI
  #define MTK_MINICLI_ENABLE
  #define MTK_CLI_TEST_MODE_ENABLE

  #define MTK_WIFI_API_TEST_CLI_ENABLE   
#endif

//------------------------------------------------------------------------------
#define ZNT_ATCI      
//------------------------------------------------------------------------------
#ifdef ZNT_ATCI
  #define MTK_ATCI_ENABLE
  //#define MTK_WIFI_AT_COMMAND_ENABLE
  //#define ZNT_WIFI_AT_COMMAND_ENABLE

  //#define ATCI_AWS_COMMAND_ENABLE
  //#define ATCI_ICTK_COMMAND_ENABLE
  

  //#define MTK_ATCI_VIA_PORT_SERVICE
  //#define MTK_PORT_SERVICE_ENABLE
#endif

//------------------------------------------------------------------------------
#undef ZNT_DEBUG // undef before release           
//------------------------------------------------------------------------------
#ifdef ZNT_DEBUG
  #define MTK_DEBUG_LEVEL_INFO
  #define MTK_DEBUG_LEVEL_WARNING
  #define MTK_DEBUG_LEVEL_ERROR

  #define ENABLE_IOT_DEBUG
  #define ENABLE_IOT_ERROR
  #define ENABLE_IOT_INFO
  #define ENABLE_IOT_WARN

  #define ZNT_DEBUG_N9
#else
  #define MTK_DEBUG_LEVEL_NONE 
#endif


#undef ZNT_USE_EFUSE_XTRIM

//#undef ZNT_MQTT_INIT
#define ZNT_WIFI_STATUS


#define ZNT_DELTA_QOS_UP

//------------------------------------------------------------------------------
//---   TEST   -----------------------------------------------------------------
//------------------------------------------------------------------------------

#define ZNT_TEST_1

#define ZNT_TEST_2

#endif /* __GLOBAL_H__ */
