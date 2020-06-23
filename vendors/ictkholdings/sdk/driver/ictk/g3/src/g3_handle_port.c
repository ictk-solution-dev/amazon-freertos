#include "g3_handle_port.h"


static void g3_communication_complete_callback(uint8_t slave_address, hal_i2c_callback_event_t event, void *user_data)
{
  BaseType_t xHigherPriorityTaskWoken = pdFALSE;
  ((g3_handle_t*)user_data)->CommunicationResult = event;
  xQueueSendFromISR( ((g3_handle_t*)user_data)->xQueueCommunicationProcess, &(((g3_handle_t*)user_data)->CommunicationResult), &xHigherPriorityTaskWoken );
  portYIELD_FROM_ISR( xHigherPriorityTaskWoken );
}

int g3_handle_init(g3_handle_t * g3_handle)
{
  
  hal_pinmux_set_function(G3_I2C_SDA, G3_I2C_SDA_FUNCTION_I2C); // Set the pin to GPIO mode.
  hal_pinmux_set_function(G3_I2C_SCL, G3_I2C_SCL_FUNCTION_I2C); // Set the pin to GPIO mode.
 
  g3_handle->Port                                   = HAL_I2C_MASTER_0;
  g3_handle->Config.frequency                       = HAL_I2C_FREQUENCY_100K;
  g3_handle->SendConfig.slave_address              = G3_SLAVE_ADDR;
  g3_handle->SendConfig.send_packet_length         = 1;
  g3_handle->ReceiveConfig.slave_address           = G3_SLAVE_ADDR;
  g3_handle->ReceiveConfig.receive_packet_length   = 1;
  
  if(HAL_I2C_STATUS_OK != hal_i2c_master_init( g3_handle->Port, &g3_handle->Config ))
  {
    return ERR_GENERAL;
  }
  
  if (HAL_I2C_STATUS_OK != hal_i2c_master_register_callback(g3_handle->Port, g3_communication_complete_callback, (void*)g3_handle)) 
  {
    return ERR_GENERAL;
  }
  
  g3_handle->xQueueCommunicationProcess = xQueueCreate( G3_COMM_PROCESS_QUEUE_LENGTH, G3_COMM_PROCESS_QUEUE_ITEM_SIZE );
  
  if( g3_handle->xQueueCommunicationProcess == NULL )
  {
  /* The queue could not be created. */
    return ERR_GENERAL;
  }
  /* Rest of code goes here. */
    
  return G3_OK;

}

int g3_handle_wakeup(g3_handle_t * g3_handle, uint32_t wli_delay_us, uint32_t whi_delay_us)
{

  hal_pinmux_set_function(G3_I2C_SDA, G3_I2C_SDA_FUNCTION_GPIO); // Set the pin to GPIO mode.
  hal_gpio_set_direction(G3_I2C_SDA, HAL_GPIO_DIRECTION_OUTPUT);
   
  hal_gpio_set_output(G3_I2C_SDA, HAL_GPIO_DATA_LOW);
  hal_gpt_delay_us(wli_delay_us);
  hal_gpio_set_output(G3_I2C_SDA, HAL_GPIO_DATA_HIGH);
  hal_gpt_delay_us(whi_delay_us);
  
  hal_pinmux_set_function(G3_I2C_SDA, G3_I2C_SDA_FUNCTION_I2C); // Set the pin to GPIO mode. 

  return G3_OK;
 
}


int g3_handle_send_command(g3_handle_t * g3_handle, uint8_t *command, uint32_t length)
{
  g3_handle->SendConfig.send_data = command;
  g3_handle->SendConfig.send_bytes_in_one_packet = length;
  
  if( hal_i2c_master_send_dma_ex( g3_handle->Port, &g3_handle->SendConfig ) != HAL_I2C_STATUS_OK )
  {
    return ERR_COMMUNICATION;
  }
                        
  if( xQueueReceive( g3_handle->xQueueCommunicationProcess, &g3_handle->CommunicationResult, ( TickType_t ) G3_PROCESS_TIMEOUT ) != pdPASS )
  {
    return ERR_COMMUNICATION;
  }
  
  if( g3_handle->CommunicationResult != G3_OK )
    return ERR_COMMUNICATION;
   
  return G3_OK;
  
}

int g3_handle_receive_response(g3_handle_t * g3_handle, uint8_t *response, uint32_t length)
{
 

  g3_handle->ReceiveConfig.receive_buffer = response;
  g3_handle->ReceiveConfig.receive_bytes_in_one_packet = length;
  
  if( hal_i2c_master_receive_dma_ex( g3_handle->Port, &g3_handle->ReceiveConfig ) != HAL_I2C_STATUS_OK )
  {
    return ERR_COMMUNICATION;
  }
  
  if( xQueueReceive( g3_handle->xQueueCommunicationProcess, &g3_handle->CommunicationResult, (TickType_t)G3_PROCESS_TIMEOUT ) != pdPASS )
  {
    return ERR_COMMUNICATION;
  }
  
  if( g3_handle->CommunicationResult != G3_OK )
    return ERR_COMMUNICATION;
  
  return G3_OK;
 
}
int g3_handle_get_status(g3_handle_t * g3_handle){

  hal_i2c_running_status_t running_status;
  hal_i2c_master_get_running_status(g3_handle->Port,&running_status);
  if(running_status.running_status == HAL_I2C_STATUS_BUS_BUSY)
    return 1;
  else
    return 0;
}
