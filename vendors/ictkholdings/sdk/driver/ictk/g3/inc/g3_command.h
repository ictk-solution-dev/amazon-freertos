/** 
  *****************************************************************************
  * @file    		    : G3command.h
  * @author         : Department 1, R&D Center, Security SoC Division
  * @version        : V1.0.0
  * @date           : 14-June-2016
  * @test processor : STM32F405RGT
  * @test compiler  : IAR ARM 7.7
  * @brief          : Header of G3command.c file.
  *****************************************************************************
  * Copyright (c) 2016 ICTK Co., LTD. All rights reserved.
  */

#ifndef __G3COMMAND_H
#define __G3COMMAND_H

/* Includes ------------------------------------------------------------------*/
#include "g3_define.h"


/* Exported functions --------------------------------------------------------*/   
int G3_Cmd(uint8_t cmd, uint8_t p1, uint16_t p2, uint8_t *sBuf, uint16_t sBufLen, uint8_t* rBuf,uint16_t* rBufLen);
int G3_Cmd_buf(uint8_t *sBuf, uint16_t sBufLen, uint8_t* rBuf,uint16_t* rBufLen);
unsigned short G3_Cmd_APDU(uint8_t ins, uint8_t p1, uint16_t p2, uint8_t *sData, uint16_t sDataLen, uint8_t* rBuf,uint16_t* rBufLen);
unsigned short G3_Cmd_BUFFER(uint8_t *sData, uint16_t sDataLen, uint8_t* rBuf,uint16_t* rBufLen);
#endif /*__G3COMMAND_H*/

/************************ (c) COPYRIGHT 2016 ICTK Co., LTD. *****END OF FILE*****/