/* 
  *****************************************************************************
  * @file           : puf_if.c
  * @author         : Department 1, R&D Center, Security SoC Division
  * @version        : V1.0.0
  * @date           : 21-June-2017
  * @brief          : Communication Layer of g3 Library
  *****************************************************************************
  * Copyright (c) 2017 ICTK Co., LTD. All rights reserved.
  */
    
#include <string.h> // needed for memset(), memcmp()
#include "puf_if.h"
#include "syslog.h"

#include "FreeRTOS.h"
#include "task.h"

#define G3_LOG  0
log_create_module(puf_if, PRINT_LEVEL_INFO);

static void _puf_calculate_crc16(uint8_t length, uint8_t *data, uint8_t *crc16);
static int _puf_check_crc16(uint8_t *response);
/******************************************************************
1. PUF I/F
******************************************************************/

/**
  * @brief  Wakes the chip.
  *         When wakeup response is not matched, set the chip(g3) to idle mode and try to wake up again.
  * @return g3 error code
  */
int _puf_wakeup_idle( void )
{
  int ret_code = G3_ERR_INTERCHIP_WAKE_UP_ERROR;
  uint8_t wake_read_data[4] = {0x04,0x11,0x33,0x43};    // status code after wake-up
  uint8_t rtemp[G3_RSP_SIZE_MAX];
  uint32_t whi_delay_time[2] =  {150,20000}; // idle, sleep

  for(int i = 0; i < 100; i++)
  {
    memset(rtemp, 0x00, sizeof(rtemp));
    ret_code = g3p_wakeup(WAKE_LOW_DURATION, whi_delay_time[0]);    // Wake-up signal
    //vTaskDelay(whi_delay_time[0]); 
    hal_gpt_delay_us(whi_delay_time[0]);
    
    for( int j = 0; j < 2; j++)
    {
      if( j == 1 )
        hal_gpt_delay_us(whi_delay_time[1]);
      
      ret_code = g3p_receive_response(rtemp, 4); 

      if(ret_code == G3_OK)
      {
        if(memcmp(rtemp, wake_read_data, 4) == 0)   // Confirms G3 has received a normal proper Wake-up.
        {
#if G3_LOG          
          LOG_I(puf_if,"wake-up success");
          LOG_I(puf_if,"wake-up response : 0x%02X 0x%02X 0x%02X 0x%02X", rtemp[0],rtemp[1],rtemp[2],rtemp[3]);
#endif
          return G3_OK;    
          
        }
        else
        {
#if G3_LOG          
          LOG_I(puf_if,"wake-up failed");          
          LOG_I(puf_if,"wake-up response : 0x%02X 0x%02X 0x%02X 0x%02X", rtemp[0],rtemp[1],rtemp[2],rtemp[3]);
#endif
          break; 
        }
      }
    }
    g3p_idle();
    hal_gpt_delay_us(whi_delay_time[0]);
  }
  return G3_ERR_INTERCHIP_WAKE_UP_ERROR;
}


/**
  * @brief  Wakes the chip.
  *         When wakeup response is not matched, set the chip(g3) to sleep mode and try to wake up again.
  * @return g3 error code
  */
int _puf_wakeup_sleep( void )
{
  int ret_code = G3_ERR_INTERCHIP_WAKE_UP_ERROR;
  uint8_t wake_read_data[4] = {0x04,0x11,0x33,0x43};    // status code after wake-up
  uint8_t rtemp[G3_RSP_SIZE_MAX];
  uint32_t whi_delay_time[2] =  {1,20}; // idle, sleep 

  for(int i = 0; i < 100; i++)
  {
    memset(rtemp, 0x00, sizeof(rtemp));
    ret_code = g3p_wakeup(WAKE_LOW_DURATION, whi_delay_time[0]);    // Wake-up signal
    
    for( int j = 0; j < 2; j++)
    {
      if( j == 1 )
        //vTaskDelay(whi_delay_time[1]);
        hal_gpt_delay_ms(whi_delay_time[1]);
      
      ret_code = g3p_receive_response(rtemp, 4);  
      if(ret_code == G3_OK)
      {
        if(memcmp(rtemp, wake_read_data, 4) == 0)   // Confirms G3 has received a normal proper Wake-up.
        {
         // LOG_I(puf_if,"wake-up success \r\n");
          //LOG_I(puf_if,"wake-up response : 0x%02X 0x%02X 0x%02X 0x%02X \r\n", rtemp[0],rtemp[1],rtemp[2],rtemp[3]);
          return G3_OK;    
          
        }
        else
        {
         // LOG_I(puf_if,"wake-up response : (retry i, j : %d, %d) 0x%02X 0x%02X 0x%02X 0x%02X \r\n", i, j, rtemp[0],rtemp[1],rtemp[2],rtemp[3]);

          break; 
        }
      }
    }
    g3p_sleep();
    ///vTaskDelay(whi_delay_time[0]);
    hal_gpt_delay_ms(whi_delay_time[0]);
  }
  return G3_ERR_INTERCHIP_WAKE_UP_ERROR;
}

/**
  * @brief  Changes the chip status to idle mode
  * @return g3 error code
  */
int _puf_toIdle( void )
{
  return g3p_idle();     // idle
}

/**
  * @brief  Changes the chip status to sleep mode
  * @return g3 error code
  */
int _puf_toSleep( void )
{
  return g3p_sleep();     // sleep
}

/**
  * @brief  Without changing the power mode, sends the command to g3 and return the response from g3 
  * @param  sBuf     Pointer to command buffer
                     format : ins code | p1 | p2 | optional data 
  * @param  sBufLen  length of the sBuf 
  * @param  rBuf     Pointer to response buffer
  * @param  rBufLen  length of the data to read 
  * @return g3 error code
  */
int _puf_sendNRecv( uint8_t* sBuf, uint32_t sBufLen, uint8_t* rBuf, uint32_t* rBufLen )
{
  int ret_code = G3_ERR_INTERCHIP_COMMUNICATION_ERROR;
  uint16_t u16_retry_cnt;
  uint8_t tx_buffer[512];
  uint8_t rx_buffer[512];
  
  uint8_t state = 0;  // send : 0 , receive : 1
  
  memset(tx_buffer, 0x00, sizeof(tx_buffer));
  memset(rx_buffer, 0x00, sizeof(rx_buffer));

  // 1. Check Parameter 
  if (!sBuf || !rBuf || !tx_buffer|| !rx_buffer || !rBufLen) return G3_ERR_INVALID_PARAMETER;
  
  if( *rBufLen > G3_RSP_SIZE_MAX ) return G3_ERR_RSP_SIZE;

  // 2. Make Packet
  //tx_buffer[G3_LENGTH_INDEX] = sBufLen + 3; // G3_LEN_SIZE + G3_CRC_SIZE
  //memcpy(&tx_buffer[G3_INSCODE_INDEX], sBuf, sBufLen);        // Write command index for data
  memcpy(&tx_buffer[0], &sBuf[1], sBufLen);
  
  uint8_t ins = tx_buffer[G3_INSCODE_INDEX];
  uint8_t p2  = tx_buffer[G3_P2_INDEX_2];
  
  // 3. Calculate CRC
  //_puf_calculate_crc16(tx_buffer[G3_LENGTH_INDEX] - G3_CRC_SIZE, tx_buffer, tx_buffer + tx_buffer[G3_LENGTH_INDEX] - G3_CRC_SIZE);
  
#if G3_LOG          
    //LOG_I(g3_test,"*************************** send packet with CRC ***************************");
    LOG_HEXDUMP_I(puf_if,"packet : ",tx_buffer, tx_buffer[G3_LENGTH_INDEX]);    
#endif 
    
  // 4. Command & Response    
  for(int i = 0; i < G3_SEND_RECEIVE_RETRY_COUNT; i++)
  {    
    if( i > 0 )
      //vTaskDelay(1);    
      hal_gpt_delay_us(500);
    
    if( state == 0 )
    {
      //Send Command 
      for(u16_retry_cnt = 0; u16_retry_cnt < G3_SEND_RETRY_COUNT; u16_retry_cnt++)
      {
        ret_code = g3p_send_command(tx_buffer);
        if(ret_code == G3_OK){
          state = 1;
          break;
        }
        
        // Wait minimum command execution time and then start polling for a response.
        ///vTaskDelay(1);
        hal_gpt_delay_ms(1);
      }    
    }
    
    if( state == 1 )
    {
      //Receive Response
      for(u16_retry_cnt = 0; u16_retry_cnt < G3_RECEIVE_RETRY_COUNT; u16_retry_cnt++)
      {
        ret_code = g3p_receive_response(rx_buffer, *rBufLen + 3);   // receive response
        if(ret_code == G3_OK)
          break;

        if( ( ins == 0x90 ) ||
            ( ( ins == 0x87 ) && (( p2 == 0x00 )||( p2 == 0x01 )) ) ||
            ( ( ins == 0x86 ) && (( p2 == 0x00 )||( p2 == 0x01 )) ) )
        {
          //vTaskDelay(30);	
          hal_gpt_delay_ms(30);
        }
        else
        {
          //vTaskDelay(1);
          hal_gpt_delay_ms(3);
        }
      }  
    }
    
    if(ret_code != G3_OK)
    {
      state = 0;
      continue;
    }
    
#if G3_LOG   
    //LOG_I(g3_test,"*************************** receive packet with CRC ***************************");
    LOG_HEXDUMP_I(puf_if,"rx packet : ",rx_buffer, *rBufLen + 3);    
#endif   
    
    // 5. Check CRC
    ret_code = _puf_check_crc16(rx_buffer);      
    if( ret_code != G3_OK )
    {
      LOG_I(puf_if,"Check CRC Error");
      g3p_reset();     
      continue;
    }
   
    if( (rx_buffer[G3_LENGTH_INDEX]-3) == 1 )
    {
      if( rx_buffer[1] != 0x00 )
      {
        if( (rx_buffer[1] == 0x01) || (rx_buffer[1] == 0x69) )
          ret_code = G3_ERR_INTERCHIP_INS_FAIL;
        else if( rx_buffer[1] == 0x03 )
          ret_code = G3_ERR_INTERCHIP_PARSE_ERROR;
        else if( rx_buffer[1] == 0x0F )
          ret_code = G3_ERR_INTERCHIP_EXECUTION_ERROR;
        else
          ret_code = G3_ERR_INTERCHIP_COMMUNICATION_ERROR;
      }
    }
    else if( (rx_buffer[G3_LENGTH_INDEX]-3) == 2 ) // verify password
    {
      if( rx_buffer[1] == 0x63 )
        ret_code = G3_ERR_INTERCHIP_INS_FAIL;
    }
//    else if( *rBufLen != (rx_buffer[G3_LENGTH_INDEX]-3) ) // invalid size
//      ret_code = G3_ERR_DIFF_RSP_SIZE;
//    else
//      ret_code = G3_OK;
    
    break;
  }

//  *rBufLen = rx_buffer[G3_LENGTH_INDEX] - 3;
//  memcpy(rBuf, rx_buffer + 1, *rBufLen);

  *rBufLen = rx_buffer[G3_LENGTH_INDEX];
  memcpy(rBuf, rx_buffer, *rBufLen);
  
  return ret_code;
}
                                                      
/**
  * @brief  Sends the command to g3 and return the response from g3 
  * @param  sBuf     Pointer to command buffer
                     format : ins code | p1 | p2 | optional data 
  * @param  sBufLen  length of the sBuf 
  * @param  rBuf     Pointer to response buffer
  * @param  rBufLen  length of the data to read
  * @return g3 error code
  */
int puf_sendNRecv( uint8_t* sBuf, uint32_t sBufLen, uint8_t* rBuf, uint32_t* rBufLen )
{
  int ret_code = G3_OK;

  ret_code = _puf_wakeup_idle();
  if( G3_OK != ret_code )
  {
    return ret_code;
  }

  ret_code = _puf_sendNRecv( sBuf, sBufLen, rBuf, rBufLen ) ;
  if( G3_OK != ret_code )
  {
    _puf_toIdle() ;
    return ret_code;
  }

  ret_code = _puf_toIdle() ;
  if( G3_OK != ret_code )
  {
    return ret_code;
  }

  return ret_code;
	
}
    
/**
  * @brief  This function calculates CRC value.
  * @param  length  length of the data to be calculated.
  * @param  data    pointer to data buffer
  * @param  crc16   pointer to crc value
  * @return none
  */    
static void _puf_calculate_crc16(uint8_t length, uint8_t *data, uint8_t *crc16)
{
  uint8_t counter;
  uint16_t crc16_register = 0;
  uint16_t polynomial = 0x8005;      // polynomial : 0x8005
  uint8_t shift_register;
  uint8_t data_bit, crc16_bit;

  for(counter = 0; counter < length; counter++)
  {
    for(shift_register = 0x01; shift_register > 0x00; shift_register <<= 1)
    {
      data_bit = (data[counter] & shift_register) ? 1 : 0;
      crc16_bit = crc16_register >> 15;

      crc16_register <<= 1;
      if((data_bit ^ crc16_bit) != 0)
        crc16_register ^= polynomial;
    }
  }
  crc16[0] = (uint8_t) (crc16_register);
  crc16[1] = (uint8_t) (crc16_register >> 8);
}

/**
  * @brief  This function checks the consistency of a response.
  * @param  response pointer to response
  * @return status of the consistency check
  */
static int _puf_check_crc16(uint8_t *response)
{
  uint8_t crc16[2];
  uint8_t length;

  length = response[0] - 2;
  _puf_calculate_crc16(length, response, crc16);

  return (crc16[0] == response[length] && crc16[1] == response[length + 1])
    ? G3_OK : G3_ERR_INTERCHIP_COMMUNICATION_ERROR;
}
