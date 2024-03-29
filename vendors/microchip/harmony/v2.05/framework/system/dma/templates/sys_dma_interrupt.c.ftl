<#--
/*******************************************************************************
  System DMA Service Interrupt Handler Template File

  File Name:
    sys_dma_interrupt.c

  Summary:
    This file contains source code necessary to initialize the system.

  Description:
    This file contains source code necessary to run the system.  It
	generates code that is added to system_interrupt.c in order to handle
	all interrupts.
 *******************************************************************************/

/*******************************************************************************
Copyright (c) 2013-2014 released Microchip Technology Inc.  All rights reserved.

Microchip licenses to you the right to use, modify, copy and distribute
Software only when embedded on a Microchip microcontroller or digital signal
controller that is integrated into your product or third party product
(pursuant to the sublicense terms in the accompanying license agreement).

You should refer to the license agreement accompanying this Software for
additional information regarding your rights and obligations.

SOFTWARE AND DOCUMENTATION ARE PROVIDED AS IS WITHOUT WARRANTY OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION, ANY WARRANTY OF
MERCHANTABILITY, TITLE, NON-INFRINGEMENT AND FITNESS FOR A PARTICULAR PURPOSE.
IN NO EVENT SHALL MICROCHIP OR ITS LICENSORS BE LIABLE OR OBLIGATED UNDER
CONTRACT, NEGLIGENCE, STRICT LIABILITY, CONTRIBUTION, BREACH OF WARRANTY, OR
OTHER LEGAL EQUITABLE THEORY ANY DIRECT OR INDIRECT DAMAGES OR EXPENSES
INCLUDING BUT NOT LIMITED TO ANY INCIDENTAL, SPECIAL, INDIRECT, PUNITIVE OR
CONSEQUENTIAL DAMAGES, LOST PROFITS OR LOST DATA, COST OF PROCUREMENT OF
SUBSTITUTE GOODS, TECHNOLOGY, SERVICES, OR ANY CLAIMS BY THIRD PARTIES
(INCLUDING BUT NOT LIMITED TO ANY DEFENSE THEREOF), OR OTHER SIMILAR COSTS.
 *******************************************************************************/
 -->
<#macro SYS_DMA_INTERRUPT_FUNCTION CHANNEL_NUMBER DMA_CHANNEL ISR_VECTOR INT_PRIO INT_SRC>
<#if CONFIG_USE_3RDPARTY_RTOS>
<#if CONFIG_3RDPARTY_RTOS_USED == "ThreadX">
void __ISR(${ISR_VECTOR}, ipl${INT_PRIO}SOFT) _IntHandlerSysDmaCh${CHANNEL_NUMBER}(void)
<#else>
<#if CONFIG_3RDPARTY_RTOS_USED == "embOS">
void __attribute__( (interrupt(ipl${INT_PRIO}AUTO), vector(${ISR_VECTOR}))) IntHandlerSysDmaInstance${CHANNEL_NUMBER}_ISR( void );
</#if>
void IntHandlerSysDmaInstance${CHANNEL_NUMBER}(void)
</#if>
<#else>
void __ISR(${ISR_VECTOR}, ipl${INT_PRIO}AUTO) _IntHandlerSysDmaCh${CHANNEL_NUMBER}(void)
</#if>
{          
<#if CONFIG_USE_3RDPARTY_RTOS>
<#if CONFIG_3RDPARTY_RTOS_USED == "ThreadX">
   /* Call ThreadX context save.  */
   _tx_thread_context_save();
</#if>
<#if CONFIG_3RDPARTY_RTOS_USED == "embOS">
    OS_EnterNestableInterrupt();
</#if>
</#if>
    SYS_DMA_TasksISR(sysObj.sysDma, ${DMA_CHANNEL});
<#if CONFIG_USE_3RDPARTY_RTOS>
<#if CONFIG_3RDPARTY_RTOS_USED == "ThreadX">
   /* Call ThreadX context restore.  */
   _tx_thread_context_restore();
</#if>
<#if CONFIG_3RDPARTY_RTOS_USED == "embOS">
    OS_LeaveNestableInterrupt();
</#if>
</#if>
}

</#macro>

<#if CONFIG_SYS_DMA_INTERRUPT_MODE_CH0 == true>
<@SYS_DMA_INTERRUPT_FUNCTION CHANNEL_NUMBER="0" DMA_CHANNEL=CONFIG_SYS_DMA_CHANNEL_ID_IDX0 
ISR_VECTOR=CONFIG_SYS_DMA_ISR_VECTOR_CH0 INT_PRIO=CONFIG_SYS_DMA_INT_PRIO_NUM_CH0
INT_SRC=CONFIG_SYS_DMA_ISR_SOURCE_CH0/>
</#if>
<#if CONFIG_SYS_DMA_INTERRUPT_MODE_CH1 == true>
<@SYS_DMA_INTERRUPT_FUNCTION CHANNEL_NUMBER="1" DMA_CHANNEL=CONFIG_SYS_DMA_CHANNEL_ID_IDX1 
ISR_VECTOR=CONFIG_SYS_DMA_ISR_VECTOR_CH1 INT_PRIO=CONFIG_SYS_DMA_INT_PRIO_NUM_CH1
INT_SRC=CONFIG_SYS_DMA_ISR_SOURCE_CH1/>

</#if>
<#if CONFIG_SYS_DMA_INTERRUPT_MODE_CH2 == true>
<@SYS_DMA_INTERRUPT_FUNCTION CHANNEL_NUMBER="2" DMA_CHANNEL=CONFIG_SYS_DMA_CHANNEL_ID_IDX2 
ISR_VECTOR=CONFIG_SYS_DMA_ISR_VECTOR_CH2 INT_PRIO=CONFIG_SYS_DMA_INT_PRIO_NUM_CH2
INT_SRC=CONFIG_SYS_DMA_ISR_SOURCE_CH2/>

</#if>
<#if CONFIG_SYS_DMA_INTERRUPT_MODE_CH3 == true>
<@SYS_DMA_INTERRUPT_FUNCTION CHANNEL_NUMBER="3" DMA_CHANNEL=CONFIG_SYS_DMA_CHANNEL_ID_IDX3 
ISR_VECTOR=CONFIG_SYS_DMA_ISR_VECTOR_CH3 INT_PRIO=CONFIG_SYS_DMA_INT_PRIO_NUM_CH3
INT_SRC=CONFIG_SYS_DMA_ISR_SOURCE_CH3/>

</#if>
<#if CONFIG_SYS_DMA_INTERRUPT_MODE_CH4 == true>
<@SYS_DMA_INTERRUPT_FUNCTION CHANNEL_NUMBER="4" DMA_CHANNEL=CONFIG_SYS_DMA_CHANNEL_ID_IDX4 
ISR_VECTOR=CONFIG_SYS_DMA_ISR_VECTOR_CH4 INT_PRIO=CONFIG_SYS_DMA_INT_PRIO_NUM_CH4
INT_SRC=CONFIG_SYS_DMA_ISR_SOURCE_CH4/>

</#if>
<#if CONFIG_SYS_DMA_INTERRUPT_MODE_CH5 == true>
<@SYS_DMA_INTERRUPT_FUNCTION CHANNEL_NUMBER="5" DMA_CHANNEL=CONFIG_SYS_DMA_CHANNEL_ID_IDX5
ISR_VECTOR=CONFIG_SYS_DMA_ISR_VECTOR_CH5 INT_PRIO=CONFIG_SYS_DMA_INT_PRIO_NUM_CH5
INT_SRC=CONFIG_SYS_DMA_ISR_SOURCE_CH5/>

</#if>
<#if CONFIG_SYS_DMA_INTERRUPT_MODE_CH6 == true>
<@SYS_DMA_INTERRUPT_FUNCTION CHANNEL_NUMBER="6" DMA_CHANNEL=CONFIG_SYS_DMA_CHANNEL_ID_IDX6 
ISR_VECTOR=CONFIG_SYS_DMA_ISR_VECTOR_CH6 INT_PRIO=CONFIG_SYS_DMA_INT_PRIO_NUM_CH6
INT_SRC=CONFIG_SYS_DMA_ISR_SOURCE_CH6/>

</#if>
<#if CONFIG_SYS_DMA_INTERRUPT_MODE_CH7 == true>
<@SYS_DMA_INTERRUPT_FUNCTION CHANNEL_NUMBER="7" DMA_CHANNEL=CONFIG_SYS_DMA_CHANNEL_ID_IDX7 
ISR_VECTOR=CONFIG_SYS_DMA_ISR_VECTOR_CH7 INT_PRIO=CONFIG_SYS_DMA_INT_PRIO_NUM_CH7
INT_SRC=CONFIG_SYS_DMA_ISR_SOURCE_CH7/>
</#if>
