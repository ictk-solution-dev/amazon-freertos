/*
 * Copyright 2019, Cypress Semiconductor Corporation or a subsidiary of
 * Cypress Semiconductor Corporation. All Rights Reserved.
 * 
 * This software, associated documentation and materials ("Software")
 * is owned by Cypress Semiconductor Corporation,
 * or one of its subsidiaries ("Cypress") and is protected by and subject to
 * worldwide patent protection (United States and foreign),
 * United States copyright laws and international treaty provisions.
 * Therefore, you may use this Software only as provided in the license
 * agreement accompanying the software package from which you
 * obtained this Software ("EULA").
 * If no EULA applies, Cypress hereby grants you a personal, non-exclusive,
 * non-transferable license to copy, modify, and compile the Software
 * source code solely for use in connection with Cypress's
 * integrated circuit products. Any reproduction, modification, translation,
 * compilation, or representation of this Software except as specified
 * above is prohibited without the express written permission of Cypress.
 *
 * Disclaimer: THIS SOFTWARE IS PROVIDED AS-IS, WITH NO WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, NONINFRINGEMENT, IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. Cypress
 * reserves the right to make changes to the Software without notice. Cypress
 * does not assume any liability arising out of the application or use of the
 * Software or any product or circuit described in the Software. Cypress does
 * not authorize its products for use in any products where a malfunction or
 * failure of the Cypress product may reasonably be expected to result in
 * significant property damage, injury or death ("High Risk Product"). By
 * including Cypress's product in a High Risk Product, the manufacturer
 * of such system or application assumes all risk of such use and in doing
 * so agrees to indemnify Cypress against all liability.
 */

/** @file
 *
 */

#include <stdint.h>
#include "typedefs.h"

#include "osl.h"
#include "hndsoc.h"

#include "wiced_platform.h"
#include "platform_peripheral.h"
#include "platform_appscr4.h"
#include "platform_toolchain.h"

#include "wwd_assert.h"
#include "wwd_rtos.h"

#ifdef __cplusplus
extern "C" {
#endif


/******************************************************
 *                      Macros
 ******************************************************/

/******************************************************
 *                    Constants
 ******************************************************/

#define ASCU_REGBASE            (PLATFORM_CHIPCOMMON_REGBASE(0x200))

/* The bits in the Interrupt Status and Mask Registers */
#define ASCU_ASTP_INT_MASK              (0x04)
#define ASCU_TX_START_AVB_INT_MASK      (0x02)
#define ASCU_RX_START_AVB_INT_MASK      (0x01)
#define ASCU_INTR_BIT_SHIFT_OFFSET      (0x09)
#define ASCU_ALL_INTS                   (ASCU_RX_START_AVB_INT_MASK |\
                                         ASCU_TX_START_AVB_INT_MASK |\
                                         ASCU_ASTP_INT_MASK)

/* ChipCommon ASCU Rx IntStatus and IntMask register bit */
#define ASCU_RX_CC_INT_STATUS_MASK      (1 << 9)

/* ChipCommon ASCU Tx IntStatus and IntMask register bit */
#define ASCU_TX_CC_INT_STATUS_MASK      (1 << 10)

/* ChipCommon ASCU Astp IntStatus and IntMask register bit */
#define ASCU_ASTP_CC_INT_STATUS_MASK    (1 << 11)

/* Network tick timer constants */
#define ONE_BILLION_RAW                 (1000000000)
#define NET_TIMER_TICKS_PER_SEC_RAW     (160000000)
#define ONE_BILLION                     ((uint64_t)ONE_BILLION_RAW)
#define NET_TIMER_TICKS_PER_SEC         ((uint64_t)NET_TIMER_TICKS_PER_SEC_RAW)
#define NET_TIMER_NANOSECS_PER_TICK     ((double)ONE_BILLION_RAW/(double)NET_TIMER_TICKS_PER_SEC_RAW)

#define ASCU_BITSEL_CONTROL_FSYNC_MASK  (0x3E000000)
#define ASCU_BITSEL_CONTROL_FSYNC_SHIFT (25)
#define ASCU_FSYNC_POWER_OF_TWO_FACTOR  (12)

#define ASCU_CONTROL_FW_TIMER_SAMPLE    (0x80)
#define ASCU_CONTROL_ENABLE_UPDATE_MASK (0x01)

/*
 * The Audio Timer clock is generated by the audio PLL.
 * The audio PLL should be configured to divide the audio PLL VCO by a factor of 4 to generate the following Audio Timer clock frequencies:
 * - 196,608,000.00Hz for Fs = M/N*8kHz    (i.e. 8,12,16,24,32,48,64,96,192kHz)
 * - 180,633,599.98Hz for Fs = N*11.025kHz (i.e. 11.025,22.05,44.1,88.2kHz)
 */
#define AUDIO_TIMER_TICKS_PER_SEC_11025_HZ (180633600)
#define AUDIO_TIMER_TICKS_PER_SEC_8000_HZ  (196608000)

/******************************************************
 *                   Enumerations
 ******************************************************/

/******************************************************
 *                 Type Definitions
 ******************************************************/

/******************************************************
 *                    Structures
 ******************************************************/

/*
 * AVB Timestamp structure.
 * Note that this structure needs to match the definition
 * used in the driver firmware in src/wl/sys/wlc.h
 */

typedef struct wlc_avb_timestamp_s {
    volatile uint32_t lock;
    volatile uint32_t avb_timestamp;
    volatile uint32_t tsf_l;
    volatile uint32_t net_timer_rxlo;
    volatile uint32_t net_timer_rxhi;
    volatile uint32_t clock_source;
    volatile uint32_t as_seconds;
    volatile uint32_t as_nanosecs;
    volatile uint32_t as_avb_timestamp;
    volatile uint32_t as_net_timer_rx_lo;
    volatile uint32_t as_net_timer_rx_hi;
    volatile uint32_t end;
} wlc_avb_timestamp_t;

typedef struct ascu_register_s {
    volatile uint32_t ascu_control;
    volatile uint32_t ascu_gpio_control;
    volatile uint32_t ascu_bitsel_control;
    volatile uint32_t master_clk_offset_lo;
    volatile uint32_t master_clk_offset_hi;
    volatile uint32_t network_clk_offset;
    volatile uint32_t start_i2s0_ts;
    volatile uint32_t start_i2s1_ts;
    volatile uint16_t interrupt_status;
    volatile uint16_t pad0;
    volatile uint16_t interrupt_mask;
    volatile uint16_t pad1;
    volatile uint32_t audio_timer_tx_lo;
    volatile uint32_t audio_timer_tx_hi;
    volatile uint32_t audio_timer_rx_lo;
    volatile uint32_t audio_timer_rx_hi;
    volatile uint32_t audio_timer_frame_sync_lo;
    volatile uint32_t audio_timer_frame_sync_hi;
    volatile uint32_t audio_timer_fw_lo;
    volatile uint32_t audio_timer_fw_hi;
    volatile uint32_t audio_talker_timer_fw_lo;
    volatile uint32_t audio_talker_timer_fw_hi;
    volatile uint32_t network_timer_tx_lo;
    volatile uint32_t network_timer_tx_hi;
    volatile uint32_t network_timer_rx_lo;
    volatile uint32_t network_timer_rx_hi;
    volatile uint32_t network_timer_frame_sync_lo;
    volatile uint32_t network_timer_frame_sync_hi;
    volatile uint32_t network_timer_fw_lo;
    volatile uint32_t network_timer_fw_hi;
    volatile uint32_t sample_cnt0;
    volatile uint32_t sample_cnt1;
} ascu_register_t;

typedef struct
{
    uint32_t ntimer_hi;
    uint32_t ntimer_lo;
    uint32_t audio_timer_hi;
    uint32_t audio_timer_lo;
    uint32_t audio_talker_timer_hi;
    uint32_t audio_talker_timer_lo;
} ascu_network_audio_time_t;

/******************************************************
 *               Function Declarations
 ******************************************************/

void platform_ascu_enable_interrupts(uint32_t int_mask);
void platform_ascu_disable_interrupts(uint32_t int_mask);

int platform_ascu_read_ntimer(uint32_t *secs, uint32_t *nanosecs);
int platform_ascu_read_fw_ntimer(uint32_t *secs, uint32_t *nanosecs);
volatile wlc_avb_timestamp_t* platform_ascu_get_avb_ts(void);

platform_result_t platform_ascu_get_audio_timer_resolution(uint32_t audio_sample_rate, uint32_t *ticks_per_sec);
platform_result_t platform_ascu_set_frame_sync_period(uint32_t frame_count);
platform_result_t platform_ascu_set_frame_sync_offset( uint32_t offset_hi, uint32_t offset_lo );
platform_result_t platform_ascu_read_frame_sync_audio_timer(uint32_t *time_hi, uint32_t *time_lo);
platform_result_t platform_ascu_read_fw_audio_timer(uint32_t *time_hi, uint32_t *time_lo);
platform_result_t platform_ascu_read_fw_audio_talker_timer(uint32_t *time_hi, uint32_t *time_lo);
platform_result_t platform_ascu_read_raw_ntimer(uint32_t *timer_hi, uint32_t *timer_lo);
platform_result_t platform_ascu_read_raw_fw_ntimer(uint32_t *timer_hi, uint32_t *timer_lo);
platform_result_t platform_ascu_read_fw_timers(ascu_network_audio_time_t *fw_timers);
platform_result_t platform_ascu_convert_ntimer(uint32_t ntimer_hi, uint32_t ntimer_lo, uint32_t *secs, uint32_t *nanosecs);
platform_result_t platform_ascu_convert_atimer(uint32_t sample_rate, uint32_t atimer_hi, uint32_t atimer_lo, uint32_t *secs, uint32_t *nanosecs);
