#ifndef __GPIO_SLEEP_CONFIG_H__
#define __GPIO_SLEEP_CONFIG_H__


#define SLEEP_ENABLE            0x1
#define SLEEP_DISABLE           0x0

#define PINMUX_AON_SLEEP_ENABLE_GPIO0           SLEEP_ENABLE
#define PINMUX_AON_SLEEP_ENABLE_GPIO1           SLEEP_ENABLE
#define PINMUX_AON_SLEEP_ENABLE_GPIO2           SLEEP_ENABLE
#define PINMUX_AON_SLEEP_ENABLE_GPIO3           SLEEP_ENABLE
#define PINMUX_AON_SLEEP_ENABLE_GPIO4           SLEEP_ENABLE
#define PINMUX_AON_SLEEP_ENABLE_GPIO5           SLEEP_ENABLE
#define PINMUX_AON_SLEEP_ENABLE_GPIO6           SLEEP_ENABLE
#define PINMUX_AON_SLEEP_ENABLE_GPIO7           SLEEP_DISABLE        //Don�t use IO sleep function
#define PINMUX_AON_SLEEP_ENABLE_GPIO24          SLEEP_ENABLE
#define PINMUX_AON_SLEEP_ENABLE_GPIO25          SLEEP_ENABLE
#define PINMUX_AON_SLEEP_ENABLE_GPIO26          SLEEP_ENABLE
#define PINMUX_AON_SLEEP_ENABLE_GPIO32          SLEEP_ENABLE
#define PINMUX_AON_SLEEP_ENABLE_GPIO31          SLEEP_ENABLE
#define PINMUX_AON_SLEEP_ENABLE_GPIO27          SLEEP_ENABLE
#define PINMUX_AON_SLEEP_ENABLE_GPIO30          SLEEP_ENABLE
#define PINMUX_AON_SLEEP_ENABLE_GPIO28          SLEEP_ENABLE
#define PINMUX_AON_SLEEP_ENABLE_GPIO29          SLEEP_ENABLE
#define PINMUX_AON_SLEEP_ENABLE_GPIO60          SLEEP_ENABLE
#define PINMUX_AON_SLEEP_ENABLE_GPIO59          SLEEP_ENABLE
#define PINMUX_AON_SLEEP_ENABLE_GPIO58          SLEEP_ENABLE
#define PINMUX_AON_SLEEP_ENABLE_GPIO57          SLEEP_ENABLE
#define PINMUX_AON_SLEEP_ENABLE_GPIO39          SLEEP_ENABLE
#define PINMUX_AON_SLEEP_ENABLE_GPIO38          SLEEP_ENABLE
#define PINMUX_AON_SLEEP_ENABLE_GPIO37          SLEEP_ENABLE
#define PINMUX_AON_SLEEP_ENABLE_GPIO36          SLEEP_ENABLE
#define PINMUX_AON_SLEEP_ENABLE_GPIO35          SLEEP_ENABLE
#define PINMUX_AON_SLEEP_ENABLE_GPIO34          SLEEP_ENABLE
#define PINMUX_AON_SLEEP_ENABLE_GPIO33          SLEEP_ENABLE

#define NONE                    0x0
#define INPUT_HIGH_IMPEDENCE    0x0
#define OUTPUT_LOW              0x1
#define OUTPUT_HIGH             0x3
#define INPUT_PD                0x4
#define INPUT_PU                0x8

#define PINMUX_AON_SLEEP_CONFIG_GPIO0           INPUT_PD
#define PINMUX_AON_SLEEP_CONFIG_GPIO1           INPUT_HIGH_IMPEDENCE
#define PINMUX_AON_SLEEP_CONFIG_GPIO2           INPUT_PU
#define PINMUX_AON_SLEEP_CONFIG_GPIO3           OUTPUT_HIGH
#define PINMUX_AON_SLEEP_CONFIG_GPIO4           INPUT_PU
#define PINMUX_AON_SLEEP_CONFIG_GPIO5           INPUT_PU
#define PINMUX_AON_SLEEP_CONFIG_GPIO6           INPUT_PU
#define PINMUX_AON_SLEEP_CONFIG_GPIO7           NONE        //Don�t use IO sleep function
#define PINMUX_AON_SLEEP_CONFIG_GPIO24          INPUT_PU
#define PINMUX_AON_SLEEP_CONFIG_GPIO25          INPUT_PD
#define PINMUX_AON_SLEEP_CONFIG_GPIO26          INPUT_PU
#define PINMUX_AON_SLEEP_CONFIG_GPIO32          OUTPUT_HIGH
#define PINMUX_AON_SLEEP_CONFIG_GPIO31          INPUT_PD
#define PINMUX_AON_SLEEP_CONFIG_GPIO27          OUTPUT_HIGH
#define PINMUX_AON_SLEEP_CONFIG_GPIO30          OUTPUT_HIGH
#define PINMUX_AON_SLEEP_CONFIG_GPIO28          OUTPUT_HIGH
#define PINMUX_AON_SLEEP_CONFIG_GPIO29          OUTPUT_HIGH
#define PINMUX_AON_SLEEP_CONFIG_GPIO60          INPUT_PU
#define PINMUX_AON_SLEEP_CONFIG_GPIO59          INPUT_PU
#define PINMUX_AON_SLEEP_CONFIG_GPIO58          OUTPUT_LOW
#define PINMUX_AON_SLEEP_CONFIG_GPIO57          INPUT_PD
#define PINMUX_AON_SLEEP_CONFIG_GPIO39          INPUT_PD
#define PINMUX_AON_SLEEP_CONFIG_GPIO38          INPUT_HIGH_IMPEDENCE
#define PINMUX_AON_SLEEP_CONFIG_GPIO37          INPUT_PD
#define PINMUX_AON_SLEEP_CONFIG_GPIO36          OUTPUT_LOW
#define PINMUX_AON_SLEEP_CONFIG_GPIO35          INPUT_PD
#define PINMUX_AON_SLEEP_CONFIG_GPIO34          INPUT_PD
#define PINMUX_AON_SLEEP_CONFIG_GPIO33          INPUT_PD
#endif /* __GPIO_SLEEP_CONFIG_H__ */
