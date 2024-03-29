/*******************************************************************************
  Clock System Service Local Data Structures

  Company:
    Microchip Technology Inc.

  File Name:
    sys_clk_local.h

  Summary:
    Clock System Service local declarations and definitions.

  Description:
    This file contains the Clock System Service local declarations and
    definitions.
*******************************************************************************/

//DOM-IGNORE-BEGIN
/*******************************************************************************
Copyright (c) 2013 released Microchip Technology Inc.  All rights reserved.

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
//DOM-IGNORE-END

#ifndef _SYS_CLK_LOCAL_H
#define _SYS_CLK_LOCAL_H

// *****************************************************************************
// *****************************************************************************
// Section: File includes
// *****************************************************************************
// *****************************************************************************

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "system/clk/sys_clk.h"
#include "system/clk/src/sys_clk_variant_mapping.h"
#include "system/devcon/sys_devcon.h"

// DOM-IGNORE-BEGIN
#ifdef __cplusplus  // Provide C++ Compatibility

    extern "C" {

#endif
// DOM-IGNORE-END 

// *****************************************************************************
// *****************************************************************************
// Section: Data Type Definitions
// *****************************************************************************
// *****************************************************************************


// *****************************************************************************
/* Oscillator module ID used by the PLIB

  Summary:
    Configures the modules ID used by the peripheral library.

  Description:
    This macro configures the modules Id used by the peripheral library.

  Remarks:
    None.
*/

#define OSC_PLIB_ID                                                 OSC_ID_0


// *****************************************************************************
/* Oscillator System Service Hardware Instance Object

  Summary:
    Defines the object required for the maintenance of the hardware.

  Description:
    This defines the object required for the maintenance of the hardware.

  Remarks:
    None.
*/

typedef struct _SYS_CLK_OBJ_STRUCT
{
    /* This variable holds the system clock value. It is also
    used to calculate the other clocks which are derived from the system clock */
    uint32_t systemClock;

    /* Save the clock frequency which is closest to the previously
       requested frequency */
    uint32_t systemClosestClock;

    /* System clock source */
   CLK_SOURCES_SYSTEM systemClockSource;

    /* Status of the previous System clock Operation */
    SYS_CLK_STATUS systemClockStatus;

    /* This variable holds the peripheral clock value.  */
    uint32_t peripheralClock[PERIPHERAL_BUSES_MAX];

    SYS_CLK_STATUS peripheralClockStatus[PERIPHERAL_BUSES_MAX];

    uint32_t peripheralClosestClock[PERIPHERAL_BUSES_MAX];

    /* This variable holds the USB clock value.  */
    uint32_t usbClock[USB_BUSES_MAX];

    SYS_CLK_STATUS usbClockStatus[USB_BUSES_MAX];

    uint32_t usbClosestClock[USB_BUSES_MAX];

    /* This variable holds the Reference clock value. */
    uint32_t referenceClock[REFERENCE_BUSES_MAX];

    SYS_CLK_STATUS referenceClockStatus[REFERENCE_BUSES_MAX];

    uint32_t referenceClosestClock[REFERENCE_BUSES_MAX];

    SYS_CLK_ERROR_HANDLER callback;

} SYS_CLK_OBJECT;

extern SYS_CLK_OBJECT clkObject;

// *****************************************************************************
// *****************************************************************************
// Section: Data Type Definitions
// *****************************************************************************
// *****************************************************************************

// *****************************************************************************
/* System PLL lock time maximum

  Summary:
    This macro defines the maximum delay for getting the PLL to lock after
    setting the clock source.

  Description:
    This macro defines the maximum delay for getting the PLL to lock after
    setting the clock source.

  Remarks:
    None.
*/

#define SYS_CLK_SYSPLL_LOCK_DELAY_80MHZ     400

<#if CONFIG_PIC32MX = false >
// *****************************************************************************
/* CLK_REFERENCE_DIVISOR_MAX

  Summary:
    Maximum Reference Clock Divider bits

  Description:
    This macro defines the maximum divisor value for the reference oscillator control module.
    
*/

#define CLK_REFERENCE_DIVISOR_MAX   65535

// *****************************************************************************
/* CLK_REFERENCE_TRIM_MAX

  Summary:
    Maximum Reference Clock Trim bits

  Description:
    This macro defines the maximum trim value for the reference oscillator control module.

*/

#define CLK_REFERENCE_TRIM_MAX 511
</#if>

// *****************************************************************************
// *****************************************************************************
// Section: Function Prototypes
// *****************************************************************************
// *****************************************************************************

/******************************************************************************
  Function:
    unsigned int SYS_CLK_SystemClockSet ( SYS_CLK_SOURCE clockSource,
                                            unsigned long clockFrequency )
  Summary:
    Sets the clock source and frequency for the system clock.

  Description:
    This function sets the clock frequency and source for the system clock.

  Remarks:
    None.
*/

unsigned int SYS_CLK_SystemClockSet (   CLK_SOURCES_SYSTEM clockSource,
                                        unsigned long clockFrequency );


/******************************************************************************
  Function:
    unsigned long SYS_CLK_PeripheralClockSet ( SYS_CLK_SOURCE clockSource,
						unsigned long clockFrequency )
  Summary:
    Sets the clock source and frequency for the peripheral clock.

  Description:
    This function sets the clock frequency and source for the peripheral clock.

  Remarks:
    None.
*/

unsigned long SYS_CLK_PeripheralClockSet ( CLK_SOURCES_SYSTEM clockSource,
					   unsigned long clockFrequency );


/******************************************************************************
  Function:
    bool SYS_CLK_FrequencyErrorCheck( unsigned long inpFreq,
                                        unsigned long acheivedFreq )
  Summary:
    Checks whether the difference between the user requested clock rate and
    the maximum achievable clock is within limits.

  Description:
    This function checks whether the difference between the user requested clock
    rate and the maximum achievable clock is within limits.

  Returns:
    - true  - The difference between clocks is within limits
    - false - The difference between clocks is not within limits

  Remarks:
    None.
*/

bool SYS_CLK_FrequencyErrorCheck(unsigned long inpFreq,
                                    unsigned long acheivedFreq);


/******************************************************************************
  Function:
    unsigned long SYS_CLK_ClosestFactorsGet(    unsigned long sourceFrequency,
                                                unsigned long requestedFrequency,
                                                unsigned char *valueToReg1,
                                                unsigned char *valueToReg2 )

  Summary:
    Gets the value of the multiplier and divisor that is closest to the
    expected value for the system PLL.

  Description:
    This function gets the value of the multiplier and divisor that is closest
    to the expected value for the system PLL.

  Remarks:
    None.
*/

unsigned long SYS_CLK_ClosestFactorsGet(   unsigned long sourceFrequency,
                                           unsigned long requestedFrequency,
                                           unsigned char *valueToPLLMULT,
                                           unsigned char *valueToPLLODIV );

<#if CONFIG_PIC32WK = true >
/******************************************************************************
  Function:
    unsigned long SYS_CLK_USBClockClosestFactorsGet(    
                                                unsigned long requestedFrequency,
                                                unsigned char *valueToReg1,
                                                unsigned char *valueToReg2 
												   )

  Summary:
    Gets the value of the multiplier and divisor that is closest to the
    expected value for the USB PLL.

  Description:
    This function gets the value of the multiplier and divisor that is closest
    to the expected value for the USB PLL.

  Remarks:
    None.
*/

unsigned long SYS_CLK_USBClockClosestFactorsGet(   unsigned long requestedFrequency,
                                           unsigned char *valueToPLLMULT,
                                           unsigned char *valueToPLLODIV );

</#if>										   
/******************************************************************************
  Function:
    unsigned long SYS_CLK_ReferenceClockSet ( SYS_CLK_SOURCE clockSource,
                                                unsigned long clockFrequency )
  Summary:
    Sets the clock source and frequency of the reference clock.

  Description:
    This function sets the clock frequency and source for the reference clock.

  Remarks:
    None.
*/

unsigned long SYS_CLK_ReferenceClockSet ( CLK_SOURCES_REFERENCE clockSource,
                                            unsigned long clockFrequency );



/******************************************************************************
  Function:
    char SYS_CLK_ReferenceClosestDivisorGet( unsigned char regValue,
						unsigned char *valueToReg )

  Summary:
    Gets the value of the reference clock divisor that is closest to the
    expected value.

  Description:
    This function gets the value of the reference clock divisor that is closest
    to the expected value.

  Remarks:
    None.
*/

char SYS_CLK_ReferenceClosestDivisorGet( unsigned char regValue,
                                            unsigned char *valuetoWrite );


/******************************************************************************
  Function:
    void SYS_CLK_ReferenceClockSwitch( SYS_CLK_SOURCE clockSource )

  Summary:
    Initiates the clock switch for the reference clock out.

  Description:
    This function initiates the reference clock switch.

  Remarks:
    None.
*/

void SYS_CLK_ReferenceClockSwitch( CLK_SOURCES_REFERENCE clockSource );


/******************************************************************************
  Function:
   char SYS_CLK_PeripheralClosestDivisorGet( unsigned char regValue,
                                                    unsigned char *valueToReg )

  Summary:
    Gets the value of the peripheral clock divisor that is closest to the
    expected value.

  Description:
    This function gets the value of the peripheral clock divisor that is
    closest to the expected value.

  Remarks:
    None.
*/

char SYS_CLK_PeripheralClosestDivisorGet( unsigned char regValue,
                                            unsigned char *valueToReg );


// *****************************************************************************
/* Macro:
    SYS_CLK_ReferenceSourceToRegValue( factor )

  Summary:
    Converts the value of the reference clock source in the SYS_CLK_SOURCE
    enumeration to the actual value to be written to the register.

  Description:
    This macro converts the value of the reference clock source in the
    SYS_CLK_SOURCE enumeration to the actual value to be written to the register.

  Remarks:
    None.

*/

unsigned long SYS_CLK_ClosestFactorsGet(   unsigned long sourceFrequency,
                                           unsigned long requestedFrequency,
                                           unsigned char *valueToPLLMULT,
                                           unsigned char *valueToPLLODIV );


/******************************************************************************
  Function:
    int8_t SYS_CLK_SystemClockSourceSwitch ( CLK_SOURCES_SYSTEM clockSource,
                                            unsigned char valueToReg,
                                            unsigned char valueToReg2,
                                            bool waitUntilComplete )

  Summary:
    Initiates the clock switch for the system clock.

  Description:
    This function initiates the clock switch for the system clock.

  Remarks:
    None.
*/

int8_t SYS_CLK_SystemClockSourceSwitch ( CLK_SOURCES_SYSTEM clockSource,
                                            unsigned char valueToReg,
                                            unsigned char valueToReg2,
                                            bool waitUntilComplete );

<#if CONFIG_PIC32MX = false >
/******************************************************************************
  Function:
    uint32_t _SYS_CLK_PLLInputDividerRead ( void )

  Summary:
    Reads the value of the PLL Input Divider.

  Description:
    This function will read from the configuration the current value for the
    PLL Input Divider.  The value is translated from the configuration bit into
 *  the intended divider value.

  Remarks:
    None.
*/

uint32_t _SYS_CLK_PLLInputDividerRead ( void );


/******************************************************************************
  Function:
    uint32_t _SYS_CLK_PLLMultiplierRead ( void )

  Summary:
    Reads the value of the PLL Multiplier.

  Description:
    This function will read from the configuration the current value for the
    PLL Multiplier.  The value is translated from the configuration bit into
 *  the intended multiplier value.

  Remarks:
    None.
*/

uint32_t _SYS_CLK_PLLMultiplierRead ( void );

/******************************************************************************
  Function:
    uint32_t _SYS_CLK_PLLOutputDividerRead ( void )

  Summary:
    Reads the value of the PLL Output Divider.

  Description:
    This function will read from the configuration the current value for the
    PLL Output Divider.  The value is translated from the configuration bit into
 *  the intended divider value.

  Remarks:
    None.
*/

uint32_t _SYS_CLK_PLLOutputDividerRead ( void );
</#if>
<#if CONFIG_PIC32WK = true >
/******************************************************************************
  Function:
    uint32_t _SYS_CLK_UPLLInputDividerRead ( void )

  Summary:
    Reads the value of the USB PLL Input Divider.

  Description:
    This function will read from the configuration the current value for the
    USB PLL Input Divider.  The value is translated from the configuration bit 
	into the intended divider value.

  Remarks:
    None.
*/

uint32_t _SYS_CLK_UPLLInputDividerRead ( void );


/******************************************************************************
  Function:
    uint32_t _SYS_CLK_UPLLMultiplierRead ( void )

  Summary:
    Reads the value of the USB PLL Multiplier.

  Description:
    This function will read from the configuration the current value for the
    USB PLL Multiplier.  The value is translated from the configuration bit into
 *  the intended multiplier value.

  Remarks:
    None.
*/

uint32_t _SYS_CLK_UPLLMultiplierRead ( void );

/******************************************************************************
  Function:
    uint32_t _SYS_CLK_UPLLOutputDividerRead ( void )

  Summary:
    Reads the value of the USB PLL Output Divider.

  Description:
    This function will read from the configuration the current value for the
    USB PLL Output Divider.  The value is translated from the configuration bit 
	into the intended divider value.

  Remarks:
    None.
*/

uint32_t _SYS_CLK_UPLLOutputDividerRead ( void );

/******************************************************************************
  Function:
	OSC_SYS_TYPE _SYS_CLK_ClockSourceMap (CLK_SOURCES_SYSTEM clockSource)

  Summary:
    Maps the value of the CLK_SOURCES_SYSTEM to OSC_SYS_TYPE.

  Description:
    This function will map the enumerations from CLK_SOURCES_SYSTEM to 
	OSC_SYS_TYPE.

  Remarks:
    None.
*/

OSC_SYS_TYPE _SYS_CLK_ClockSourceMap (CLK_SOURCES_SYSTEM clockSource);

</#if>
/******************************************************************************
  Function:
   uint32_t SYS_CLK_FRCClosestDivisorGet ( unsigned char regValue,
                            unsigned char *valueToReg, uint32_t requestedFrequency )

  Summary:
    Gets the value of the FRC clock divisor that is closest to the
    expected value.

  Description:
    This function gets the value of the FRC clock divisor that is
    closest to the expected value.

  Remarks:
    None.
*/
uint32_t SYS_CLK_FRCClosestDivisorGet ( unsigned char regValue,
                            unsigned char *valueToReg, uint32_t requestedFrequency );

uint32_t _SYS_CLK_SystemClockRead ( void );

bool _SYS_CLK_PeripheralFrequencySet ( CLK_BUSES_PERIPHERAL peripheralBus,
        uint32_t peripheralClockHz,
        uint32_t *clockClosest );
<#if CONFIG_HAVE_REFCLOCK = true >
bool _SYS_CLK_ReferenceFrequencySet ( CLK_BUSES_REFERENCE referenceBus, CLK_SOURCES_REFERENCE referenceSource,
            uint32_t referenceClockHz, bool waitUntilComplete, uint32_t *clockClosest );

void _SYS_CLK_ReferenceClockSetup ( CLK_BUSES_REFERENCE referenceBus, SYS_CLK_REFERENCE_SETUP *refSetup );
</#if>
bool _SYS_CLK_SystemClockSet ( CLK_SOURCES_SYSTEM systemSource,
	uint32_t systemClockHz, bool waitUntilComplete, uint32_t *clockClosest );

uint32_t _SYS_CLK_PeripheralClockRead ( CLK_BUSES_PERIPHERAL peripheralBus, uint32_t systemClockHz);

OSC_PERIPHERAL_BUS _SYS_CLK_GetOscPeripheralBus ( CLK_BUSES_PERIPHERAL peripheralBus );


//DOM-IGNORE-BEGIN
#ifdef __cplusplus
}
#endif
//DOM-IGNORE-END

#endif //#ifndef _SYS_CLK_LOCAL_H

/*******************************************************************************
 End of File
*/

