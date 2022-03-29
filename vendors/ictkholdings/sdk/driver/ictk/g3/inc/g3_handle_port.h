#ifndef __G3_HANDLE_PORT_H__
#define __G3_HANDLE_PORT_H__

#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
#include "hal.h"
#include "g3_define.h"

#ifdef __cplusplus
extern "C" {
#endif
  
typedef struct {
  
  hal_i2c_port_t Port;
  hal_i2c_config_t Config;
  hal_i2c_send_config_t SendConfig;
  hal_i2c_receive_config_t ReceiveConfig;
  QueueHandle_t xQueueCommunicationProcess;
  uint32_t CommunicationResult;
  
} g3_handle_t;

#define G3_SLAVE_ADDR   0xC8>>1

#define G3_I2C_SCL HAL_GPIO_8
#define G3_I2C_SDA HAL_GPIO_9

#define G3_I2C_SCL_FUNCTION_GPIO        0
#define G3_I2C_SCL_FUNCTION_I2C         4
#define G3_I2C_SDA_FUNCTION_GPIO        0
#define G3_I2C_SDA_FUNCTION_I2C         4

#define G3_PROCESS_TIMEOUT              10000
#define G3_COMM_PROCESS_QUEUE_LENGTH    1   
#define G3_COMM_PROCESS_QUEUE_ITEM_SIZE sizeof( uint32_t )  




int g3_handle_init(g3_handle_t * g3_handle);
int g3_handle_wakeup(g3_handle_t * g3_handle, uint32_t wli_delay_us, uint32_t whi_delay_us);
int g3_handle_send_command(g3_handle_t * g3_handle, uint8_t *command, uint32_t length);
int g3_handle_receive_response(g3_handle_t * g3_handle, uint8_t *response, uint32_t length);
int g3_handle_get_status(g3_handle_t * g3_handle);

#ifdef __cplusplus
}
#endif

#endif /* __G3_HANDLE_PORT_H__ */
