/** 
  *****************************************************************************
  * @file               : g3_i2c.c
  * @author             : Department 1, R&D Center, Security SoC Division
  * @version            : V1.0.6
  * @date               : 25-April-2019
  * @brief              : Functions for I2C Physical Hardware Independent Layer of G3 Library
  *****************************************************************************
  * Copyright (c) 2017 ICTK Co., LTD. All rights reserved.
  */

#include <stdio.h>
#include <string.h>
#include "g3_i2c.h"

#include "FreeRTOS.h"
#include "task.h"

#ifdef ICTK_G3_I2C_DMA
#include "g3_handle_port.h"
#else
#include "i2c_sw.h"
#endif

#ifdef ICTK_G3_I2C_DMA
uint8_t _send_data[1024]         @ ".noncached_ram_zidata";
uint8_t _receive_data[1024]      @ ".noncached_ram_zidata";

g3_handle_t g3_handle;

static int g3p_i2c_send(uint8_t instruction_flag, uint8_t *send_data, uint32_t length)
{
  _send_data[0] = instruction_flag;
  memcpy( _send_data + 1, send_data, length );
  return g3_handle_send_command( &g3_handle, _send_data, length + 1);
}
    
int g3p_init(void)
{
  return g3_handle_init( &g3_handle );  
}

/**
  * @brief  This I2C function generates a Wake-up pulse and delays.
  * @param  delay_time Wake-up low duration 
  * @return status of the operation
  */
int g3p_wakeup(uint32_t wli_delay_time, uint32_t whi_delay_time)
{
  return g3_handle_wakeup( &g3_handle, wli_delay_time, whi_delay_time );
}

/**
  * @brief  This I2C function resets the I/O buffer of the G3 device.
  * @return status of the operation
  */
int g3p_reset(void)  // I2C RESET Word Address Value : 0x00
{
  _send_data[0] = G3_I2C_WORDADDRESS_RESET;
  return g3_handle_send_command(&g3_handle, _send_data, 1);
}

/**
  * @brief  This I2C function puts the G3 device into low-power state.
  * @return status of the operation
  */
int g3p_sleep(void)  // I2C SLEEP Word Address Value : 0x01
{
  _send_data[0] = G3_I2C_WORDADDRESS_SLEEP;
  return g3_handle_send_command(&g3_handle, _send_data, 1);
}

/**
  * @brief  This I2C function puts the G3 device into idle state.
  * @return status of the operation
  */
int g3p_idle(void)  // I2C IDLE Word Address Value : 0x02 
{
  _send_data[0] = G3_I2C_WORDADDRESS_IDLE;
  return g3_handle_send_command(&g3_handle, _send_data, 1);
}

/**
  * @brief  This I2C function sends a command to the device.
  * @param  command  pointer to command buffer
  * @return status of the operation
  */
int g3p_send_command(uint8_t *command)  // I2C COMMAND Word Address Value : 0x03  
{  
  return g3p_i2c_send(G3_I2C_WORDADDRESS_COMMAND, command, command[0]); 
}

/**
  * @brief  This I2C function receives a response from the G3 device.
  * @param  response  pointer to rx buffer
  * @return status of the operation
  */
int g3p_receive_response(uint8_t *response, uint32_t length)
{
  int result;
  
  result = g3_handle_receive_response( &g3_handle, _receive_data, length );
  memcpy( response, _receive_data, length );
  
  return result;
}
int g3p_i2c_get_status()
{
  return g3_handle_get_status( &g3_handle);
}
#else
/**
  * @brief  This function sends a I2C packet enclosed by a I2C start and stop to a G3 device.
  * @param  instruction_flag value listed in instruction flag
  * @param  pData pointer to data buffer
  * @param  Size number of bytes in data buffer
  * @return status of the operation
  */
static int g3p_i2c_send(uint8_t instruction_flag, uint8_t *pData, uint32_t Size)
{
  int32_t ret_code = G3_OK;

  taskENTER_CRITICAL(); 
  ret_code = _i2c_start();
  if(ret_code != G3_OK)
  {
    _i2c_stop();
    taskEXIT_CRITICAL();
    return ret_code;
  }
  
  _i2c_sendbyte(G3_DEFAULT_I2C_DEVICE_ADDRESS & 0xFE);
  
  ret_code = _i2c_waitack();
  if(ret_code != G3_OK)
  {
    _i2c_stop();
    taskEXIT_CRITICAL();
    return ret_code;
  }

  _i2c_sendbyte(instruction_flag);
  
  ret_code = _i2c_waitack();
  if(ret_code != G3_OK)
  {
    _i2c_stop();
    taskEXIT_CRITICAL();
    return ret_code;
  }    

  while(Size--)
  {
    _i2c_sendbyte(*pData);
    
    ret_code = _i2c_waitack();
    if(ret_code != G3_OK)
    {
      _i2c_stop();
      taskEXIT_CRITICAL();
      return ret_code;
    }
    pData++;
    
  }
  _i2c_stop();

  taskEXIT_CRITICAL();
  return ret_code;
}

/**
  * @brief  This I2C function generates a Wake-up pulse and delays.
  * @param  delay_time Wake-up low duration 
  * @return status of the operation
  */
int g3p_wakeup(uint32_t wli_delay_time, uint32_t whi_delay_time)
{
  int32_t ret = G3_OK;

    
  taskENTER_CRITICAL();
  //_i2c_wakeup(0x00, &wakeup, 1);
  ret = _i2c_wakeup(wli_delay_time, whi_delay_time);
  taskEXIT_CRITICAL();
  
  return ret;
}

/**
  * @brief  This I2C function resets the I/O buffer of the G3 device.
  * @return status of the operation
  */
int g3p_reset(void)  // I2C RESET Word Address Value : 0x00
{
  return g3p_i2c_send(G3_I2C_WORDADDRESS_RESET, NULL, 0);
}

/**
  * @brief  This I2C function puts the G3 device into low-power state.
  * @return status of the operation
  */
int g3p_sleep(void)  // I2C SLEEP Word Address Value : 0x01
{
  return g3p_i2c_send(G3_I2C_WORDADDRESS_SLEEP, NULL, 0);
}

/**
  * @brief  This I2C function puts the G3 device into idle state.
  * @return status of the operation
  */
int g3p_idle(void)  // I2C IDLE Word Address Value : 0x02 
{
  return g3p_i2c_send(G3_I2C_WORDADDRESS_IDLE, NULL, 0);
}

/**
  * @brief  This I2C function sends a command to the device.
  * @param  command  pointer to command buffer
  * @return status of the operation
  */
int g3p_send_command(uint8_t *command)  // I2C COMMAND Word Address Value : 0x03  
{  
  return g3p_i2c_send(G3_I2C_WORDADDRESS_COMMAND, command, command[0]); 
}

/**
  * @brief  This I2C function receives a response from the G3 device.
  * @param  response  pointer to rx buffer
  * @return status of the operation
  */
int g3p_receive_response(uint8_t *response, uint32_t length)
{
  //G3_StatusTypeDef ret_code = G3_ERROR;
  int32_t ret_code = G3_OK;

  taskENTER_CRITICAL();

  ret_code = _i2c_start();
  if(ret_code != G3_OK)
  {
    _i2c_stop();
    taskEXIT_CRITICAL();    
    return ret_code;
  }

  _i2c_sendbyte(G3_DEFAULT_I2C_DEVICE_ADDRESS | 0x01);
  
  ret_code = _i2c_waitack();
  if(ret_code != G3_OK)
  {
    _i2c_stop();
    taskEXIT_CRITICAL();    
    return ret_code;
  }

  *response = _i2c_receivebyte();
  if(*response == 0xFF)
  {
    _i2c_noack();    
    _i2c_stop();  
    taskEXIT_CRITICAL();    
    return G3_ERR_BUSY;
  }
  else
  {
    _i2c_ack();          
    if( response[0] == 0x00)
    {
      _i2c_stop();  
      taskEXIT_CRITICAL();      
      return G3_OK;
    }
    length--;
    response++;
  }

  
  while(length)
  {
    *response = _i2c_receivebyte();
    
    if(length == 1)
      _i2c_noack();
    else
      _i2c_ack(); 
    
    response++;
    length--;   
  }
  _i2c_stop();    

  taskEXIT_CRITICAL();  
  return ret_code;
}
#endif

/************************ (c) COPYRIGHT 2017 ICTK Co., LTD. *****END OF FILE*****/
