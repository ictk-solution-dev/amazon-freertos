/** 
  *****************************************************************************
  * @file               : g3_i2c.h
  * @author             : Department 1, R&D Center, Security SoC Division
  * @version            : V1.0.6
  * @date               : 25-April-2019
  * @brief              : Header of g3_i2c.c file.
  *****************************************************************************
  * Copyright (c) 2017 ICTK Co., LTD. All rights reserved.
  */

#ifndef __G3_I2C_H
#define __G3_I2C_H

/* Includes ------------------------------------------------------------------*/
#include "g3_define.h"
/* Variables ------------------------------------------------------------------*/

/* Defines ------------------------------------------------------------------*/


/* Exported functions --------------------------------------------------------*/  

int g3p_init(void);
int g3p_wakeup(uint32_t wli_delay_time, uint32_t whi_delay_time);
int g3p_reset(void);
int g3p_sleep(void);
int g3p_idle(void);
int g3p_send_command(uint8_t *command);
int g3p_receive_response(uint8_t *response, uint32_t length);

int g3p_i2c_send(uint8_t instruction_flag, uint8_t *pData, uint32_t Size);
int g3p_i2c_get_status(void);
#endif /*__G3_I2C_H*/

/************************ (c) COPYRIGHT 2017 ICTK Co., LTD. *****END OF FILE*****/

