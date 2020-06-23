/** 
  *****************************************************************************
  * @file               : i2c_sw.c
  * @author             : Department 1, R&D Center, Security SoC Division
  * @version            : V1.0.0
  * @date               : 25-April-2019
  * @brief              : Functions of I2C Hardware Dependent Part of G3 Physical Layer
  *                     Using GPIO For Communication
  *****************************************************************************
  * Copyright (c) 2017 ICTK Co., LTD. All rights reserved.
  */

#include "i2c_sw.h"


//------------------------------------------------------------------------------
extern GPIO_BASE_REGISTER_T *gpio_base;




//------------------------------------------------------------------------------
int _i2c_init(void)
{
  hal_gpio_status_t ret;
  hal_pinmux_status_t ret_pinmux_status;

  ret = hal_gpio_init(HAL_GPIO_8);    /// SCL
  ret = hal_gpio_init(HAL_GPIO_9);    /// SDA
  ret_pinmux_status = hal_pinmux_set_function(HAL_GPIO_8, 0); // Set the pin to GPIO mode.
  ret_pinmux_status = hal_pinmux_set_function(HAL_GPIO_9, 0); // Set the pin to GPIO mode.

  ret = hal_gpio_set_direction(HAL_GPIO_8, HAL_GPIO_DIRECTION_OUTPUT);
  ret = hal_gpio_set_direction(HAL_GPIO_9, HAL_GPIO_DIRECTION_OUTPUT);

  return ret;
}

/**
  * @brief  This function creates a Start condition (SDA low, then SCL low).
  * @return status of the operation
  */
int _i2c_start(void)
{ 
  SDA_MODE_SET_OUT;
  
  SDA_H;
  SCL_H;
  hal_gpt_delay_us(I2C_CLOCK_HIGH_TIME);
  if(SDA_READ() == SDA_RESET) {
    return G3_ERR_INTERCHIP_COMMUNICATION_ERROR;///G3_I2C_START_FAIL
  }
  
  SDA_L;
  hal_gpt_delay_us(I2C_CLOCK_LOW_TIME);
  if(SDA_READ() != SDA_RESET)  {
    return G3_ERR_INTERCHIP_COMMUNICATION_ERROR;///G3_I2C_START_FAIL
  }
  
  SCL_L;
  hal_gpt_delay_us(I2C_CLOCK_LOW_TIME);
  
  return G3_OK;
}

/**
  * @brief  This function creates a Stop condition (SCL high, then SDA high).
  */
void _i2c_stop(void)
{

  SDA_MODE_SET_OUT;
  
  SCL_L;
  SDA_L;
  hal_gpt_delay_us(I2C_CLOCK_HIGH_TIME);
  
  SCL_H;
    
/////////////////// stretch //////////////////
  while(SCL_READ() == SCL_RESET);
/////////////////// stretch //////////////////
  
    
  hal_gpt_delay_us(I2C_CLOCK_HIGH_TIME);
  
  SDA_H;
  hal_gpt_delay_us(I2C_CLOCK_HIGH_TIME);
}


/**
  * @brief  Enable acknowledging data.
  */
void _i2c_ack(void)
{	
  SDA_MODE_SET_OUT;
  
  SCL_L;
  SDA_L;
  hal_gpt_delay_us(I2C_CLOCK_LOW_TIME);
  SCL_H;
  hal_gpt_delay_us(I2C_CLOCK_HIGH_TIME);
  SCL_L;
  
}



/**
  * @brief  Disable acknowledging data for the last byte.
  */
void _i2c_noack(void)
{	
  SDA_MODE_SET_OUT; 
    
  SDA_H;
  hal_gpt_delay_us(I2C_CLOCK_HIGH_TIME);
  SCL_H;
  hal_gpt_delay_us(I2C_CLOCK_HIGH_TIME);
  SCL_L;
}


/**
  * @brief  This function checks acknowledging data.
  * @return status of the operation
  */
int _i2c_waitack(void)
{
  SDA_MODE_SET_IN;  
  
  SCL_L;
  hal_gpt_delay_us(I2C_CLOCK_LOW_TIME);
  
  SCL_H;
  
  hal_gpt_delay_us(I2C_CLOCK_HIGH_TIME);  
    
  if(SDA_READ() != SDA_RESET)  
  {
    SCL_L;
    return G3_ERR_INTERCHIP_COMMUNICATION_ERROR;///G3_I2C_NO_ACK;
  }

  SCL_L;
  return G3_OK;
}


//------------------------------------------------------------------------------
/**
  * @brief  This I2C function generates a Wake-up pulse.
  * @param  delay_time Wake-up low duration
  * @return status of the operation
  */
int _i2c_wakeup(uint16_t wli_delay_time, uint16_t whi_delay_time)
{
  SDA_MODE_SET_OUT;
  
  SDA_H;
  SCL_H;
  hal_gpt_delay_us(I2C_CLOCK_HIGH_TIME);
  if (SDA_READ() == SDA_RESET) {
    return G3_ERR_INTERCHIP_WAKE_UP_ERROR;
  }

  SDA_L;
  hal_gpt_delay_us(wli_delay_time);
  SDA_H;
  hal_gpt_delay_us(whi_delay_time);

  return G3_OK;
}

/**
  * @brief  This function sends one byte to an I2C device.
  * @param  sendbyte one byte to send
  */
void _i2c_sendbyte(uint8_t sendbyte)
{
  uint8_t i=8;

  SDA_MODE_SET_OUT;
  
  while(i--)
  {
    SCL_L;
    hal_gpt_delay_us(I2C_CLOCK_LOW_TIME>>1);   //I2C_CLOCK_LOW_TIME / 2   
    if (sendbyte&0x80) {
      SDA_H;
	}
    else {
      SDA_L;   
	}
    sendbyte<<=1;
    hal_gpt_delay_us(I2C_CLOCK_LOW_TIME>>1);   //I2C_CLOCK_LOW_TIME / 2 
    SCL_H;
    
/////////////////// stretch //////////////////
    while(SCL_READ() == SCL_RESET);
/////////////////// stretch //////////////////
    
    hal_gpt_delay_us(I2C_CLOCK_HIGH_TIME);
  }
  SCL_L;
}



/**
  * @brief  This function receives one byte from an I2C device.
  * @return received byte
  */
uint8_t _i2c_receivebyte(void) 
{ 
  uint8_t i=8;
  uint8_t receivebyte=0;
  
  SDA_MODE_SET_IN;

  SDA_H;

  while(i--)
  {
    receivebyte<<=1;      
    SCL_L;
    hal_gpt_delay_us(I2C_CLOCK_LOW_TIME);
    
    SCL_H;

/////////////////// stretch //////////////////
    while(SCL_READ() == SCL_RESET);
/////////////////// stretch //////////////////
    
    hal_gpt_delay_us(I2C_CLOCK_HIGH_TIME);	
    
    if(SDA_READ() != SDA_RESET) 
    {
      receivebyte|=0x01;
    }
  }    
  SCL_L;
  return receivebyte;
}




/************************ (c) COPYRIGHT 2017 ICTK Co., LTD. *****END OF FILE*****/
