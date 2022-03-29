/****************************(C) COPYRIGHT 2016 ICTK Co., LTD.*************************************/
/* program		  	: cqueue.h 										  					                                     	*/
/* processor 	  	: STM32F405RGT									  								                             	*/
/* compiler		  	: IAR ARM 7.7 															                               			*/
/* program BY	  	: bckang																		                                    */
/* date			  	  : 2016.02.02																		                                */
/* copyright	  	: ICTK Co., LTD																                              		*/
/**************************************************************************************************/
#ifndef __CQUEUE_H
#define __CQUEUE_H

/* Includes ------------------------------------------------------------------*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "puf_if.h"
/* Defines ------------------------------------------------------------------*/
#define MAX_QUEUE       256//96
#define COM_USART1      0
#define COM_USART2      1


/* Variables ------------------------------------------------------------------*/
//typedef __packed struct {
typedef struct {
  uint8_t cqueue[MAX_QUEUE];
  uint16_t queue_head;
  uint16_t queue_tail;
} circular_queue;
extern circular_queue cq[5];
extern circular_queue usb_cq;
extern circular_queue cdc_cq;


/* Exported functions --------------------------------------------------------*/   
extern void rx_fifo_clear(uint8_t q_no);
extern void write_queue(uint8_t q_no, uint8_t qdata);
extern uint8_t rx_fifo_pop(uint8_t q_no, uint8_t *nData);
extern uint8_t check_cqueue(uint8_t q_no);

uint8_t check_usb_cqueue(void);
void write_usb_queue(uint8_t *pData);
uint8_t usb_fifo_pop(uint8_t *pData);
void usb_fifo_clear(void);

uint8_t check_cdc_cqueue(void);
void write_cdc_queue(uint8_t *pData, uint32_t len);
uint8_t cdc_fifo_pop(uint8_t *pData, uint32_t *len);
uint8_t cdc_fifo_pop2(uint8_t *pData);
void cdc_fifo_clear(void);

#endif /*__CQUEUE_H*/

/************************ (c) COPYRIGHT 2016 ICTK Co., LTD. *****END OF FILE*****/