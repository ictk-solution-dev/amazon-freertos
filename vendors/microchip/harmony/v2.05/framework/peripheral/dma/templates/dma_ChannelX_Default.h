/*******************************************************************************
  DMA Peripheral Library Template Implementation

  File Name:
    dma_ChannelX_Default.h

  Summary:
    DMA PLIB Template Implementation

  Description:
    This header file contains template implementations
    For Feature : ChannelX
    and its Variant : Default
    For following APIs :
        PLIB_DMA_ExistsChannelX
        PLIB_DMA_ChannelXEnable
        PLIB_DMA_ChannelXIsEnabled
        PLIB_DMA_ChannelXDisable

*******************************************************************************/

//DOM-IGNORE-BEGIN
/*******************************************************************************
Copyright (c) 2012 released Microchip Technology Inc.  All rights reserved.

Microchip licenses to you the right to use, modify, copy and distribute
Software only when embedded on a Microchip microcontroller or digital signal
controller that is integrated into your product or third party product
(pursuant to the sublicense terms in the accompanying license agreement).

You should refer to the license agreement accompanying this Software for
additional information regarding your rights and obligations.

SOFTWARE AND DOCUMENTATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
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

//DOM-IGNORE-END

#ifndef _DMA_CHANNELX_DEFAULT_H
#define _DMA_CHANNELX_DEFAULT_H

#include "dma_Registers.h"

//******************************************************************************
/* Function :  DMA_ExistsChannelX_Default

  Summary:
    Implements Default variant of PLIB_DMA_ExistsChannelX

  Description:
    This template implements the Default variant of the PLIB_DMA_ExistsChannelX function.
*/

#define PLIB_DMA_ExistsChannelX PLIB_DMA_ExistsChannelX
PLIB_TEMPLATE bool DMA_ExistsChannelX_Default( DMA_MODULE_ID index )
{
    return true;
}


//******************************************************************************
/* Function :  DMA_ChannelXEnable_Default

  Summary:
    Implements Default variant of PLIB_DMA_ChannelXEnable

  Description:
    This template implements the Default variant of the PLIB_DMA_ChannelXEnable function.
    Operation is atomic.
*/

PLIB_TEMPLATE void DMA_ChannelXEnable_Default( DMA_MODULE_ID index , DMA_CHANNEL channel )
{
    volatile dma_ch_register_t *regs = (dma_ch_register_t *)(index + sizeof(dma_register_t) + channel * sizeof(dma_ch_register_t));

    regs->DCHxCONSET = _DCH0CON_CHEN_MASK;
}


//******************************************************************************
/* Function :  DMA_ChannelXIsEnabled_Default

  Summary:
    Implements Default variant of PLIB_DMA_ChannelXIsEnabled

  Description:
    This template implements the Default variant of the PLIB_DMA_ChannelXIsEnabled function.
    Operation is atomic.
*/

PLIB_TEMPLATE bool DMA_ChannelXIsEnabled_Default( DMA_MODULE_ID index , DMA_CHANNEL channel )
{
    volatile dma_ch_register_t *regs = (dma_ch_register_t *)(index + sizeof(dma_register_t) + channel * sizeof(dma_ch_register_t));

    return (bool)regs->DCHxCON.CHEN;
}


//******************************************************************************
/* Function :  DMA_ChannelXDisable_Default

  Summary:
    Implements Default variant of PLIB_DMA_ChannelXDisable

  Description:
    This template implements the Default variant of the PLIB_DMA_ChannelXDisable function.
    Operation is atomic.
*/

PLIB_TEMPLATE void DMA_ChannelXDisable_Default( DMA_MODULE_ID index , DMA_CHANNEL channel )
{
    volatile dma_ch_register_t *regs = (dma_ch_register_t *)(index + sizeof(dma_register_t) + channel * sizeof(dma_ch_register_t));

    regs->DCHxCONCLR = _DCH0CON_CHEN_MASK;
}


#endif /*_DMA_CHANNELX_DEFAULT_H*/

/******************************************************************************
 End of File
*/

