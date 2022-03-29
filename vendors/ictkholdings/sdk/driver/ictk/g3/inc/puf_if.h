/** 
  *****************************************************************************
  * @file           : puf_if.h
  * @author         : Department 1, R&D Center, Security SoC Division
  * @version        : V1.0.0
  * @date           : 25-April-2019
  * @brief          : Header of puf_if.c file.
  *****************************************************************************
  * Copyright (c) 2017 ICTK Co., LTD. All rights reserved.
  */

#ifndef __PUF_IF_H
#define __PUF_IF_H

/* Includes ------------------------------------------------------------------*/
#include "g3_define.h"
#ifndef ICTK_G3_I2C_DMA
#include "i2c_sw.h"
#endif
#include "g3_i2c.h"
#include "timer.h"

/* Defines -------------------------------------------------------------------*/
/* Variables -----------------------------------------------------------------*/
/* Exported functions --------------------------------------------------------*/   
int _puf_wakeup( void );
int _puf_wakeup_idle( void );
int _puf_wakeup_sleep( void );
int _puf_toIdle( void );
int _puf_toSleep( void );
int _puf_sendNRecv( uint8_t* sBuf, uint32_t sBufLen, uint8_t* rBuf, uint32_t* rBufLen );

int puf_sendNRecv( uint8_t* sBuf, uint32_t sBufLen, uint8_t* rBuf, uint32_t* rBufLen );

#endif /*__PUF_IF_H*/

/************************ (c) COPYRIGHT 2017 ICTK Co., LTD. *****END OF FILE*****/


