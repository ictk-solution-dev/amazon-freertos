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
#include "g3_nvdm_config.h"
#include "type_def.h"
#include "nvdm_config.h"
#include "iot_test_tls.h"
#include "g3_cert.h"
#include "g3_semaphore.h"


#define AWS_IOT_DEFAULT_MQTT_HOST           ("a1osxd2p57u8ac-ats.iot.ap-northeast-2.amazonaws.com")//("a1u3jlmi4gdald-ats.iot.ap-northeast-2.amazonaws.com")
#define AWS_IOT_DEFAULT_MY_THING_NAME       ("things_g3_iot")//("Thing_ZWG3M_001")
#define AWS_IOT_DEFAULT_CLIENTID            ("ICTK_G3_ShadowClient")//("zwg3m_ShadowClient1")
#define AWS_IOT_DEFAULT_MQTT_PORT           ("8883")
#define AWS_IOT_DEFAULT_MQTT_AC             ("1") // Auto Connect

#ifdef ICTK_TLS_FOR_AWSTEST
#ifdef ICTK_TLS
#include "g3_i2c.h"
#include "base64.h"
#include "aws_clientcredential_keys.h"
#include "string.h"
#include "iot_default_root_certificates.h"
#include "ictk/profile.h"
#endif
#endif
   

/* amazon config */
static const group_data_item_t g_amazon_data_item_array[] = {
    NVDM_DATA_ITEM("Endpoint",             AWS_IOT_DEFAULT_MQTT_HOST),
    NVDM_DATA_ITEM("Thingname",            AWS_IOT_DEFAULT_MY_THING_NAME),
    NVDM_DATA_ITEM("ClientID",             AWS_IOT_DEFAULT_CLIENTID),
    NVDM_DATA_ITEM("Portnum",              AWS_IOT_DEFAULT_MQTT_PORT),
    NVDM_DATA_ITEM("Autoconn",             AWS_IOT_DEFAULT_MQTT_AC),  
};


/* user defined callback functions for each group */
static void amazon_check_default_value(void)
{
    check_default_value("amazon",
                        g_amazon_data_item_array,
                        sizeof(g_amazon_data_item_array) / sizeof(g_amazon_data_item_array[0]));
}

static void amazon_reset_to_default(void)
{
    reset_to_default("amazon",
                     g_amazon_data_item_array,
                     sizeof(g_amazon_data_item_array) / sizeof(g_amazon_data_item_array[0]));
}

static void amazon_show_value(void)
{
    show_group_value("amazon",
                     g_amazon_data_item_array,
                     sizeof(g_amazon_data_item_array) / sizeof(g_amazon_data_item_array[0]));
}



const user_data_item_operate_t g3_data_item_operate_array[] = {
    {
        "amazon",
        amazon_check_default_value,
        amazon_reset_to_default,
        amazon_show_value,
    },

};


int32_t g3_config_init(g3_cfg_t *g3_config)
{

    // init g3 profile
    uint8_t buff[PROFILE_BUF_LEN];
    uint32_t len = sizeof(buff);

    // amazon
    len = sizeof(buff);
    nvdm_read_data_item("amazon", "Endpoint", buff, &len);
    memcpy(g3_config->epoint, buff, len);
    
    len = sizeof(buff);
    nvdm_read_data_item("amazon", "Thingname", buff, &len);
    memcpy(g3_config->tname, buff, len);    

    len = sizeof(buff);
    nvdm_read_data_item("amazon", "ClientID", buff, &len);
    memcpy(g3_config->cid, buff, len);

    len = sizeof(buff);
    nvdm_read_data_item("amazon", "Portnum", buff, &len);
    g3_config->portnum = (uint16_t)atoi((char *)buff);

    len = sizeof(buff);
    nvdm_read_data_item("amazon", "Autoconn", buff, &len);
    g3_config->ac = (uint16_t)atoi((char *)buff);

    return 0;
}
