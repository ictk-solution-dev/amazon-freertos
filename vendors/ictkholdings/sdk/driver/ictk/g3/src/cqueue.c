/** 
  *****************************************************************************
  * @file    		    : cqueue.c
  * @author         : Department 1, R&D Center, Security SoC Division
  * @version        : V1.0.0
  * @date           : 14-June-2016
  * @test processor : STM32F405RGT
  * @test compiler  : IAR ARM 7.7
  * @brief          : Queue Functions
  *****************************************************************************
  * Copyright (c) 2016 ICTK Co., LTD. All rights reserved.
  */

#include <string.h>
#include "cqueue.h"

circular_queue cq[5];
circular_queue usb_cq;
circular_queue cdc_cq;

/**************************************************************************************************/
/* Function Name  : uint8_t drv_check_cqueue(uint8_t q_no)		                	                  */
/* Description    : This function use queue buffer check for uart receive data	                  */
/* Input          : q_no	- it is q number for uart number(COM1~5)		        	                  */
/* Output         : None														                                              */
/* Return         : q status valu( 0: no data, 1: data exist)					                            */
/**************************************************************************************************/
uint8_t check_cqueue(uint8_t q_no)
{
	if (cq[q_no].queue_head != cq[q_no].queue_tail)
		return 1;
	else
		return 0;
}

/**************************************************************************************************/
/* Function Name  : void drv_write_queue(uint8_t q_no, uint8_t qdata)	                            */
/* Description    : This function write in queue buffer for uart receive data		                  */
/* Input          : q_no	- it is q number for uart number(COM1~5)				                        */
/* 					qdata	- write data									                                		              */
/* Output         : None											                              				              */
/* Return         : None													                              		              */
/**************************************************************************************************/
void write_queue(uint8_t q_no, uint8_t qdata)
{
	cq[q_no].cqueue[cq[q_no].queue_head] = qdata;
	cq[q_no].queue_head = (cq[q_no].queue_head+1)%MAX_QUEUE;

}

/**************************************************************************************************/
/* Function Name  : uint8_t drv_uart_rx_fifo_pop(uint8_t q_no, uint8_t *nData )	                  */
/* Description    : This function check qbuffer and read in queue buffer for uart receive data	  */
/* Input          : q_no	- it is q number for uart number(COM1~5)							                 	*/
/* Output         : *nData	- write data															                            */
/* Return         : q status valu( 0: no data, 1: data exist)									                   	*/
/**************************************************************************************************/
uint8_t rx_fifo_pop(uint8_t q_no, uint8_t *nData )
{
	if(check_cqueue(q_no))
  {	
		*nData = cq[q_no].cqueue[cq[q_no].queue_tail];
		cq[q_no].queue_tail = (cq[q_no].queue_tail+1)%MAX_QUEUE;
		return 1;
	}
	return 0;
}

/**************************************************************************************************/
/* Function Name  : void drv_uart_rx_fifo_clear(uint8_t q_no)						                     			*/
/* Description    : This function clare qbuffer 													                        */
/* Input          : q_no	- it is q number for uart number(COM1~5)								                */
/* Output         : None																			                                    */
/* Return         : None																		                                    	*/
/**************************************************************************************************/
void rx_fifo_clear(uint8_t q_no)
{
	memset(cq[q_no].cqueue,0x00,MAX_QUEUE);
	cq[q_no].queue_head=0;
	cq[q_no].queue_tail=0;
}

uint8_t check_usb_cqueue(void)
{
	if (usb_cq.queue_head != usb_cq.queue_tail)
		return 1;
	else
		return 0;
}

void write_usb_queue(uint8_t *pData)
{
  memcpy(usb_cq.cqueue + usb_cq.queue_head, pData, 64);
	usb_cq.queue_head = (usb_cq.queue_head+64)%MAX_QUEUE;
}

uint8_t usb_fifo_pop(uint8_t *pData)
{
	if(check_usb_cqueue())
  {	
    memcpy(pData, usb_cq.cqueue + usb_cq.queue_tail, 64);
		usb_cq.queue_tail = (usb_cq.queue_tail+64)%MAX_QUEUE;
		return 1;
	}
	return 0;
}

void usb_fifo_clear(void)
{
	memset(usb_cq.cqueue,0x00,MAX_QUEUE);
	usb_cq.queue_head=0;
	usb_cq.queue_tail=0;
}

uint8_t check_cdc_cqueue(void)
{
	if (cdc_cq.queue_head != cdc_cq.queue_tail)
		return 1;
	else
		return 0;
}

void write_cdc_queue(uint8_t *pData, uint32_t len)
{
  uint32_t i;

  if((cdc_cq.queue_head + len) >= MAX_QUEUE)
  {
    for(i=cdc_cq.queue_head; i<MAX_QUEUE; i++)
    {
      cdc_cq.cqueue[i] = pData[i-cdc_cq.queue_head];
    }
    for(i=0; i<cdc_cq.queue_head + len - MAX_QUEUE; i++)
    {
      cdc_cq.cqueue[i] = pData[MAX_QUEUE-cdc_cq.queue_head+i];
    }    
    cdc_cq.queue_head = cdc_cq.queue_head + len - MAX_QUEUE;        
  }
  else
  {
    for(i=0; i<len; i++)
    {
      cdc_cq.cqueue[cdc_cq.queue_head+i] = pData[i];
    }
    cdc_cq.queue_head = cdc_cq.queue_head + len;    
  }
}

uint8_t cdc_fifo_pop(uint8_t *pData, uint32_t *len)
{
  uint32_t i;
  
	if(check_cdc_cqueue())
  {	    
    if(cdc_cq.queue_head > cdc_cq.queue_tail)
    {
      *len = cdc_cq.queue_head - cdc_cq.queue_tail;
      for(i=0; i<*len; i++)
      {
        pData[i] = cdc_cq.cqueue[cdc_cq.queue_tail+i];
      }
      cdc_cq.queue_tail = (cdc_cq.queue_tail+*len);          
    }
    else
    {
      *len = (MAX_QUEUE-cdc_cq.queue_tail) + cdc_cq.queue_head;
      for(i=cdc_cq.queue_tail; i<MAX_QUEUE; i++)
      {
        pData[i-cdc_cq.queue_tail] = cdc_cq.cqueue[i];
      }
      for(i=0; i<cdc_cq.queue_tail + *len - MAX_QUEUE; i++)
      {
        pData[MAX_QUEUE-cdc_cq.queue_tail+i] = cdc_cq.cqueue[i];
      }        
      cdc_cq.queue_tail = cdc_cq.queue_tail + *len - MAX_QUEUE;        
    }

		return 1;
	}
	return 0;
}

uint8_t cdc_fifo_pop2(uint8_t *pData)
{
	if(check_cdc_cqueue())
  {	
		*pData = cdc_cq.cqueue[cdc_cq.queue_tail];
		cdc_cq.queue_tail = (cdc_cq.queue_tail+1)%MAX_QUEUE;
		return 1;
	}
	return 0; 
}

void cdc_fifo_clear(void)
{
	memset(cdc_cq.cqueue,0x00,MAX_QUEUE);
	cdc_cq.queue_head=0;
	cdc_cq.queue_tail=0;
}

/************************ (c) COPYRIGHT 2016 ICTK Co., LTD. *****END OF FILE*****/