/** 
  *****************************************************************************
  * @file    		    : G3command.c
  * @author         : Department 1, R&D Center, Security SoC Division
  * @version        : V1.0.0
  * @date           : 14-June-2016
  * @test processor : STM32F405RGT
  * @test compiler  : IAR ARM 7.7
  * @brief          : Command Marshaling Layer of G3 Library
  *****************************************************************************
  * Copyright (c) 2016 ICTK Co., LTD. All rights reserved.
  */

#include <string.h>   // needed for memset(), memcpy()
#include "g3_define.h"
#include "g3_command.h"
#include "g3_i2c.h"

static const unsigned short CRC16TAB[256] = 
{
    0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241, 
    0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440, 
    0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,  
    0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841, 
    0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40, 
    0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41, 
    0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641, 
    0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040, 
    0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240, 
    0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441, 
    0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41, 
    0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840, 
    0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41, 
    0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40, 
    0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640, 
    0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041, 
    0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240, 
    0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441, 
    0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41, 
    0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840, 
    0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41, 
    0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40, 
    0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640, 
    0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041, 
    0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241, 
    0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440, 
    0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40, 
    0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841, 
    0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40, 
    0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41, 
    0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641, 
    0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040 
};

/**
  * @brief  This function calculates CRC16.
  * @param  length number of bytes in buffer
  * @param  data pointer to data for which CRC should be calculated
  * @param  crc16 pointer to 16-bit CRC
  */
/*void G3_calculate_crc16(uint8_t length, uint8_t *data, uint8_t *crc16)
{
    int i;
    int iCRC = 0;
    int iCRC2 = 0;

    for (i = 0; i < length; i++)
        iCRC = (iCRC >> 8) ^ CRC16TAB[(iCRC ^ data[i]) & 255];

    for (i = 0; i < 16; i++)
        iCRC2 |= ((iCRC >> i) & 1) << (15 - i);

    crc16[0] = (uint8_t)iCRC2;
    crc16[1] = (uint8_t)(iCRC2 >> 8);
}
*/


static void G3_calculate_crc16(uint8_t length, uint8_t *data, uint8_t *crc16)
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
static int G3_check_crc16(uint8_t *response)
{
	uint8_t crc16[2];
	uint8_t length;

	length = response[0] - 2;
	G3_calculate_crc16(length, response, crc16);

	return (crc16[0] == response[length] && crc16[1] == response[length + 1])
          ? G3_OK : G3_ERR_INTERCHIP_COMMUNICATION_ERROR;
}

int G3_Cmd(uint8_t ins, uint8_t p1, uint16_t p2, uint8_t *sData, uint16_t sDataLen, uint8_t* rBuf,uint16_t* rBufLen)
{
  int ret_code = G3_OK;
  uint16_t u16_retry_cnt;
  uint8_t tx_buffer[512];
  uint8_t rx_buffer[512];

  uint8_t state = 0;  // send : 0 , receive : 1

  memset(tx_buffer, 0x00, sizeof(tx_buffer));
  memset(rx_buffer, 0x00, sizeof(rx_buffer));

  // 1. Check Parameter 
  if (!rBuf || !tx_buffer|| !rx_buffer || !rBufLen) return G3_ERR_INVALID_PARAMETER;

  if( *rBufLen < G3_RSP_SIZE_MAX )
  {  
    return G3_ERR_INVALID_PARAMETER;
  }

  // 2. Make Packet
	tx_buffer[G3_LENGTH_INDEX]  = G3_CMD_SIZE_MIN + sDataLen;
	tx_buffer[G3_INSCODE_INDEX] = ins;
	tx_buffer[G3_P1_INDEX]      = p1;
	tx_buffer[G3_P2_INDEX_1]      = p2 >> 8;
	tx_buffer[G3_P2_INDEX_2]  = p2;
  
  memcpy(tx_buffer + 5, sData, sDataLen);

  
  // 3. Calculate CRC
  G3_calculate_crc16(tx_buffer[G3_LENGTH_INDEX] - G3_CRC_SIZE, tx_buffer, tx_buffer + tx_buffer[G3_LENGTH_INDEX] - G3_CRC_SIZE);
  //G3_calculate_crc16(sDataLen + 5, tx_buffer, tx_buffer + sDataLen + 5);
  
  // 4. Command & Response
   for(int i = 0; i < G3_SEND_RECEIVE_RETRY_COUNT; i++)
  {    
    if( i > 0 )
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
        hal_gpt_delay_ms(EXEC_MIN_DELAY);
      }    
    }
    
    if( state == 1 )
    {
      //Receive Response
      for(u16_retry_cnt = 0; u16_retry_cnt < G3_RECEIVE_RETRY_COUNT; u16_retry_cnt++)
      {
        //ret_code = G3p_receive_response(rx_buffer);   // receive response
        ret_code = g3p_receive_response(rx_buffer, *rBufLen + 3);
        if(ret_code == G3_OK)
          break;

        if( ( ins == 0x90 ) ||
            ( ( ins == 0x87 ) && (( p2 == 0x00 )||( p2 == 0x01 )) ) ||
            ( ( ins == 0x86 ) && (( p2 == 0x00 )||( p2 == 0x01 )) ) )
        {
          hal_gpt_delay_ms(30);
        }
        else
        {
          hal_gpt_delay_ms(3);
        }
      }  
    }
    
    if(ret_code != G3_OK)
    {
      state = 0;
      continue;
    }
    
    *rBufLen = rx_buffer[G3_LENGTH_INDEX] - 3;
    
    // 5. Check CRC
    ret_code = G3_check_crc16(rx_buffer);      
    if( ret_code != G3_OK )
    {
      g3p_reset();    
      continue;
    }
   
    if( *rBufLen == 1 )
    {
      if( rx_buffer[1] != 0x00 )
      {
        if( rx_buffer[1] != 0x01 )
        {
          if( rx_buffer[1] == 0xFF )
          {
            ret_code = 0x8FFF;
            continue;
          }
        }

        return 0x8F00 | rx_buffer[1] ; 
      }
    }

#if 0    
    if(*rBufLen != rx_buffer[G3_LENGTH_INDEX] - 3) 
    {
      ret_code = G3_INVALID_SIZE;
      continue;
    }
#endif    
    
    memcpy(rBuf, rx_buffer + 1, *rBufLen);

    ret_code = G3_OK;
    break;
  }
	return ret_code;

}


int G3_Cmd_buf(uint8_t *sBuf, uint16_t sBufLen, uint8_t* rBuf,uint16_t* rBufLen)
{

  int ret_code = G3_OK;
  uint16_t u16_retry_cnt;
  uint8_t tx_buffer[512];
  uint8_t rx_buffer[512];

  uint8_t state = 0;  // send : 0 , receive : 1
  
  memset(tx_buffer, 0x00, sizeof(tx_buffer));
  memset(rx_buffer, 0x00, sizeof(rx_buffer));
  
  // 1. Check Parameter 
  if (!sBuf || !rBuf || !tx_buffer|| !rx_buffer || !rBufLen) return G3_ERR_INVALID_PARAMETER;
      
  if( *rBufLen < G3_RSP_SIZE_MAX )
  {  
    return G3_ERR_INVALID_PARAMETER;
  }

  // 2. Make Packet
  tx_buffer[G3_LENGTH_INDEX] = sBufLen + 3; // G3_LEN_SIZE + G3_CRC_SIZE
  memcpy(&tx_buffer[G3_INSCODE_INDEX], sBuf, sBufLen);        // Write command index for data
  
  uint8_t ins = tx_buffer[G3_INSCODE_INDEX];
  uint8_t p2  = tx_buffer[G3_P2_INDEX_1];

  
  // 3. Calculate CRC
  G3_calculate_crc16(tx_buffer[G3_LENGTH_INDEX] - G3_CRC_SIZE, tx_buffer, tx_buffer + tx_buffer[G3_LENGTH_INDEX] - G3_CRC_SIZE);
  
  // 4. Command & Response    
  for(int i = 0; i < G3_SEND_RECEIVE_RETRY_COUNT; i++)
  {    
    if( i > 0 )
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
		hal_gpt_delay_ms(EXEC_MIN_DELAY);
      }    
    }
    
    if( state == 1 )
    {
      //Receive Response
      for(u16_retry_cnt = 0; u16_retry_cnt < G3_RECEIVE_RETRY_COUNT; u16_retry_cnt++)
      {
        //ret_code = G3p_receive_response(rx_buffer);   // receive response
        ret_code = g3p_receive_response(rx_buffer, *rBufLen + 3);

		if(ret_code == G3_OK)
          break;

        if( ( ins == 0x90 ) ||
            ( ( ins == 0x87 ) && (( p2 == 0x00 )||( p2 == 0x01 )) ) ||
            ( ( ins == 0x86 ) && (( p2 == 0x00 )||( p2 == 0x01 )) ) )
        {
          hal_gpt_delay_ms(30);	
        }
        else
        {
          hal_gpt_delay_ms(3);
        }
      }  
    }
    
    if(ret_code != G3_OK)
    {
      state = 0;
      continue;
    }
    
    *rBufLen = rx_buffer[G3_LENGTH_INDEX] - 3;
    
    // 5. Check CRC
    ret_code = G3_check_crc16(rx_buffer);      
    if( ret_code != G3_OK )
    {
      g3p_reset();     
      continue;
    }
   
    if( *rBufLen == 1 )
    {
      if( rx_buffer[1] != 0x00 )
      {
        if( rx_buffer[1] != 0x01 )
        {
          if( rx_buffer[1] == 0xFF )
          {
            ret_code = 0x8FFF;
            continue;
          }
        }

        return 0x8F00 | rx_buffer[1] ; 
      }
    } 
    
    memcpy(rBuf, rx_buffer + 1, *rBufLen);

    ret_code = G3_OK;
    break;
  }

  return ret_code;

}


unsigned short G3_Cmd_BUFFER(uint8_t *sData, uint16_t sDataLen, uint8_t* rBuf,uint16_t* rBufLen)
{
  int ret_code = G3_OK;
  uint32_t whi_delay_time[2] =  {150,20000}; // idle, sleep
  ret_code = g3p_wakeup(WAKE_LOW_DURATION, whi_delay_time[0]);

  if( G3_OK != ret_code )
  {
    return 0x8600 | ret_code ;
  }

  ret_code = G3_Cmd_buf(sData, sDataLen, rBuf, rBufLen);
  if( G3_OK != ret_code )
  {
    g3p_idle() ;
    return 0x8600 | ret_code ;
  }

  ret_code = g3p_idle() ;
  if( G3_OK != ret_code )
  {
    return 0x8600 | ret_code ;
  }

  return 0x0000;
	
}

unsigned short G3_Cmd_APDU(uint8_t ins, uint8_t p1, uint16_t p2, uint8_t *sData, uint16_t sDataLen, uint8_t* rBuf,uint16_t* rBufLen)
{
  int ret_code = G3_OK;

  uint32_t whi_delay_time[2] =  {150,20000}; // idle, sleep
  ret_code = g3p_wakeup(WAKE_LOW_DURATION, whi_delay_time[0]);
  if( G3_OK != ret_code )
  {
    return 0x8600 | ret_code ;
  }

  ret_code = G3_Cmd(ins, p1, p2, sData, sDataLen, rBuf, rBufLen);
  if( G3_OK != ret_code )
  {
    g3p_idle() ;
    return 0x8600 | ret_code ;
  }

  ret_code = g3p_idle() ;
  if( G3_OK != ret_code )
  {
    return 0x8600 | ret_code ;
  }
  return 0x0000;
	
}


/************************ (c) COPYRIGHT 2017 ICTK Co., LTD. *****END OF FILE*****/
