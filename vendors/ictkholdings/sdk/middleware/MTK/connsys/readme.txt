CONNSYS module usage guide

Brief:          This module is an implementation of connsys.
Usage:          GCC: Include the module with "include $(SOURCE_DIR)/middleware/MTK/connsys/module.mk" in your GCC project Makefile.
                KEIL: Drag the middleware/MTK/connsys folder to your project. Add middleware/MTK/connsys/inc to INCLUDE_PATH.
                IAR: Drag the middleware/MTK/connsys folder to your project. Add middleware/MTK/connsys/inc to "additional include directories" in IAR options setting.
Dependency:     LWIP and WiFi should also be enabled.
Notice:         None.
Relative doc:   Please refer to the WiFi related guides under the doc folder for more detail.
Example project:Please find iot_sdk_demo project or iot_sdk project under project folder.
