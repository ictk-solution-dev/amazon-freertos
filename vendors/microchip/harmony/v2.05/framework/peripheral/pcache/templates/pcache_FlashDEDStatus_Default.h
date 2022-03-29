/*******************************************************************************
  PCACHE Peripheral Library Template Implementation

  File Name:
    pcache_FlashDEDStatus_Default.h

  Summary:
    PCACHE PLIB Template Implementation

  Description:
    This header file contains template implementations
    For Feature : FlashDEDStatus
    and its Variant : Default
    For following APIs :
        PLIB_PCACHE_ExistsFlashDEDStatus
        PLIB_PCACHE_FlashDEDStatusGet
        PLIB_PCACHE_FlashDEDStatusClear

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

#ifndef _PCACHE_FLASHDEDSTATUS_DEFAULT_H
#define _PCACHE_FLASHDEDSTATUS_DEFAULT_H

#include "pcache_Registers.h"

//******************************************************************************
/* Function :  PCACHE_ExistsFlashDEDStatus_Default

  Summary:
    Implements Default variant of PLIB_PCACHE_ExistsFlashDEDStatus

  Description:
    This template implements the Default variant of the PLIB_PCACHE_ExistsFlashDEDStatus function.
*/

#define PLIB_PCACHE_ExistsFlashDEDStatus PLIB_PCACHE_ExistsFlashDEDStatus
PLIB_TEMPLATE bool PCACHE_ExistsFlashDEDStatus_Default( PCACHE_MODULE_ID index )
{
    return true;
}


//******************************************************************************
/* Function :  PCACHE_FlashDEDStatusGet_Default

  Summary:
    Implements Default variant of PLIB_PCACHE_FlashDEDStatusGet 

  Description:
    This template implements the Default variant of the PLIB_PCACHE_FlashDEDStatusGet function.
    Operation is atomic.
*/

PLIB_TEMPLATE bool PCACHE_FlashDEDStatusGet_Default( PCACHE_MODULE_ID index )
{
    volatile pfm_register_t *regs = (pfm_register_t *)index;

    return (bool)regs->PRESTAT.PFMDED;
}


//******************************************************************************
/* Function :  PCACHE_FlashDEDStatusClear_Default

  Summary:
    Implements Default variant of PLIB_PCACHE_FlashDEDStatusClear 

  Description:
    This template implements the Default variant of the PLIB_PCACHE_FlashDEDStatusClear function.
    Operation is atomic.
*/

PLIB_TEMPLATE void PCACHE_FlashDEDStatusClear_Default( PCACHE_MODULE_ID index )
{
    volatile pfm_register_t *regs = (pfm_register_t *)index;

    regs->PRESTATCLR = _PRESTAT_PFMDED_MASK;
}


#endif /*_PCACHE_FLASHDEDSTATUS_DEFAULT_H*/

/******************************************************************************
 End of File
*/

