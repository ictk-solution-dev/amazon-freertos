/* Copyright Statement:
 *
 * (C) 2019-20xx  ICTK Inc. 
 *
 */

#ifdef ICTK_AWS_IOT
#ifndef __AWS_IOT_H__
#define __AWS_IOT_H__

#include "aws_iot_mqtt_client.h"
#include "aws_iot_shadow_json_data.h"


///--- Define ------------------------------------------------------------------
#define LIMIT_I32_MAX   2147483647
#define LIMIT_I32_MIN   -2147483648
#define LIMIT_I16_MAX   32767
#define LIMIT_I16_MIN   -32768
#define LIMIT_I8_MAX    127
#define LIMIT_I8_MIN    -128

#define LIMIT_U32_MAX   4294967295
#define LIMIT_U32_MIN   0
#define LIMIT_U16_MAX   65535
#define LIMIT_U16_MIN   0
#define LIMIT_U8_MAX    255
#define LIMIT_U8_MIN    0

#define LIMIT_B1_MAX    1
#define LIMIT_B1_MIN    0



#define MAX_DELTA_COUNT   5
#define MAX_SUB_COUNT     5



///--- State -------------------------------------------------------------------
typedef enum
{
  STT_INIT      = 0,
  STT_DIS_NET,
  STT_CON_NET,
  STT_DIS_SRV,
  STT_CON_SRV,
  STT_ERR,

  STT_MAX,
  STT_PADDING = 0x7F
} aws_iot_state_type;


///--- Command : ATCI to MQTT  -------------------------------------------------
typedef enum
{
  AT2MQTT_CMD_NONE = 0,
  AT2MQTT_CMD_CONNECT,  
  AT2MQTT_CMD_PUB,
  AT2MQTT_CMD_SUB,
  AT2MQTT_CMD_UNSUB,
  AT2MQTT_CMD_DELTA,
  AT2MQTT_CMD_UPDATE,
  AT2MQTT_CMD_GET,

  AT2MQTT_CMD_MAX,
  AT2MQTT_CMD_PADDING = 0x7F
} at2mqtt_cmd_type;

typedef struct
{
  at2mqtt_cmd_type      cmd;
  uint8_t               conn;   /// 0: Connect, 1: Disconnect
} at2mqtt_connect_type;


typedef struct
{
  at2mqtt_cmd_type      cmd;
  char*                 topic;
  QoS                   qos;
  char*                 payload;
} at2mqtt_pub_type;

typedef struct
{
  at2mqtt_cmd_type      cmd;
  char*                 topic;
  QoS                   qos;
} at2mqtt_sub_type;

typedef struct
{
  at2mqtt_cmd_type      cmd;
  char*                 topic;
} at2mqtt_unsub_type;

typedef enum
{
  ACT_REPORTED = 0,
  ACT_DESIRED,

  ACT_MAX,
  ACT_PADDING = 0x7F
} act_type;

typedef union
{
  int8_t                i8;
  uint8_t               ui8;
  int16_t               i16;
  uint16_t              ui16;
  int32_t               i32;
  uint32_t              ui32;
  float                 f32;
  bool                  b1;
  char*                 str;

} value_type;

typedef struct
{
  at2mqtt_cmd_type      cmd;
  char*                 key;
  JsonPrimitiveType     type;  
} at2mqtt_delta_type;

typedef struct
{
  at2mqtt_cmd_type      cmd;
  act_type              act;
  char*                 key;
  JsonPrimitiveType     type;
  value_type            value;
} at2mqtt_update_type;

typedef union
{
  at2mqtt_cmd_type      cmd;
  at2mqtt_connect_type  connect;  
  at2mqtt_pub_type      pub;
  at2mqtt_sub_type      sub;
  at2mqtt_unsub_type    unsub;  
  at2mqtt_delta_type    delta;
  at2mqtt_update_type   update;
} at2mqtt_msg_type;

///--- Event : MQTT to ATCI ----------------------------------------------------
typedef enum
{
  MQTT2AT_EVT_NONE = 0,
  MQTT2AT_EVT_PUB,
  MQTT2AT_EVT_SUB,
  MQTT2AT_EVT_DELTA,

  MQTT2AT_EVT_MAX,
  MQTT2AT_EVT_PADDING = 0x7F
} mqtt2at_event_type;

typedef struct
{
  mqtt2at_event_type    evt;  
} mqtt2at_pub_type;

typedef union
{
  mqtt2at_event_type    evt;
  mqtt2at_pub_type      pub;
} mqtt2at_msg_type;


///-----------------------------------------------------------------------------
extern QueueHandle_t xQueue_at2mqtt;
extern QueueHandle_t xQueue_mqtt2at;



#ifdef AMADAS_DOOR_LOCK
///--- ADL to MQTT  ------------------------------------------------------------
/* Amadas Door Lock Status Type */
typedef struct
{
  uint8_t b0 : 1;     /* 0: Success             1: Failure              */
  uint8_t b2 : 2;     /* 0: No Request          1: Touch Unlock Request */
                      /* 2: NFC Unlock Request  1: RF Unlock Request    */
  uint8_t b3 : 1;     /* 0: No Request          1: Lock Request         */
  uint8_t b4 : 1;     /* 0: Door Lock           1: Door Unlock          */
  uint8_t b5 : 1;     /* 0: Door Closed         1: Door Open            */
  uint8_t b6 : 1;     /* 0: Battery High        1: Battery Low          */
  uint8_t b7 : 1;     /* 0: Door Normal         1: Door Reset/Reboot    */

} adl_bits_type;

typedef union 
{
  adl_bits_type bits;
  uint8_t       adl;
} adl_status_type;
//#define adl2mqtt_msg_type   adl_status_type

 
///--- MQTT to ADL  ------------------------------------------------------------
/* ICTK Wi-Fi Module Status Type */
typedef struct
{
  uint8_t b0 : 1;     /* Reserved                                       */      
  uint8_t b2 : 2;     /* 0: No Request          1: Unlock Request       */            
                      /* 2: Lock Request        3: Reserved             */
  uint8_t b3 : 1;     /* Reserved                                       */
  uint8_t b4 : 1;     /* Reserved                                       */      
  uint8_t b5 : 1;     /* Reserved                                       */
  uint8_t b6 : 1;     /* Reserved                                       */
  uint8_t b7 : 1;     /* 0: Connected           1: Not connected        */
} iwm_bits_type;

typedef  union
{
  iwm_bits_type bits;   
  uint8_t       iwm;
} iwm_status_type;
//#define mqtt2adl_msg_type   iwm_status_type


///-----------------------------------------------------------------------------
extern QueueHandle_t xQueue_adl2mqtt;
extern QueueHandle_t xQueue_mqtt2adl;

#endif /* AMADAS_DOOr_LOCK */



#endif /* __AWS_IOT_H__ */
#endif /* ICTK_AWS_IOT */
