Wifi_service module usage guide

Brief:
	This module provides Wi-Fi common service through Wi-Fi APIs. It must include the library when in use.
	MT5932/MT7682/MT7686/AW7698 use wifi_inic architecture. MT7687/MT7697 uses wifi_supp architecture. 
	They all have common Wi-Fi API interfaces.

Usage:
  1. For MT5932/MT7682/MT7686/AW7698:
    In feature.mk of the project, set MTK_WIFI_ROM_ENABLE=y.
	GCC: The library is in the "prebuilt/middleware/MTK/wifi_service/combo/lib/wifi_inic" folder.
	libwifi.a

	KEIL: The library is in the "prebuilt/middleware/MTK/wifi_service/combo/lib/wifi_inic" folder.
	libwifi_CM4_Keil.lib

	IAR: The library is in the "prebuilt/middleware/MTK/wifi_service/combo/lib/wifi_inic" folder.
	libwifi_CM4_IAR.a
	
  2. For MT7687/MT7697:
    In feature.mk of the project, set MTK_MINISUPP_ENABLE=y.
	GCC: The library is in the "prebuilt/middleware/MTK/wifi_service/combo/lib/wifi_supp" folder.
	libwifi.a

	KEIL: The library is in the "prebuilt/middleware/MTK/wifi_service/combo/lib/wifi_supp" folder.
	libwifi_CM4_Keil.lib

	IAR: The library is in the "prebuilt/middleware/MTK/wifi_service/combo/lib/wifi_supp" folder.
	libwifi_CM4_IAR.a
	
Dependency: 
	It is dependent on the specific library you used for the project.

Notice: 
	None

Relative doc: 
	middleware/MTK/wifi_service/combo/inc/wifi_api.h

Example project:
	MT7682 -- project/mt7682_hdk/apps/iot_sdk_demo
	MT7686 -- project/mt7686_hdk/apps/iot_sdk_demo
	MT7687 -- project/mt7687_hdk/apps/iot_sdk
	MT7697 -- project/mt7697_hdk/apps/iot_sdk
