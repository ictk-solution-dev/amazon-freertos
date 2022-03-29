Wi-Fi stack module usage guide

Brief: This module is used by the customer to compile a Wi-Fi project and load the compiled product.

Usage:
	GCC: Replace the library in the "wifi_stack/lib" folder with the correct library.
	libwifi_aw7698_ram.a
	libwifi_aw7698_ram_repeater.a
	libwifi_aw7698_ram_repeater_wps.a
	libwifi_aw7698_ram_wps.a
	libwifi_mt5932_ram.a
	libwifi_mt5932_ram_repeater.a
	libwifi_mt5932_ram_repeater_wps.a
	libwifi_mt5932_ram_wps.a
	libwifi_mt7682_ram.a
	libwifi_mt7682_ram_repeater.a
	libwifi_mt7682_ram_repeater_wps.a
	libwifi_mt7682_ram_wps.a
	libwifi_mt7686_ram.a
	libwifi_mt7686_ram_repeater.a
	libwifi_mt7686_ram_repeater_wps.a
	libwifi_mt7686_ram_wps.a

	KEIL: MT7687/MT7697 support KEIL, but MT7682/MT7686/AW7698/MT5932 do not support KEIL.
	For MT7687/MT7697, you must replace the library in the "wifi_stack/lib" folder with the correct library.
	libwifi_ram_CM4_Keil.lib
	libwifi_ram_CM4_Keil_repeater.lib
	libwifi_ram_CM4_Keil_wps.lib
	libwifi_ram_CM4_Keil_wps_repeater.lib

	IAR: Replace the library in the "wifi_stack/lib" folder with the correct library.
	libwifi_ram_CM4_IAR.a
	libwifi_ram_CM4_repeater_IAR.a
	libwifi_ram_CM4_wps_IAR.a
	libwifi_ram_CM4_repeater_wps_IAR.a

Dependency: "wifi_stack" is dependent on "wifi_service" and "wifi_service_protected". You must make sure to select the correct version.


Notice: The other files in this folder are only used for reference. They do not affect the compile process.


Relative doc: none

Example project:
MT7682 -- project/mt7682_hdk/apps/iot_sdk_demo
MT7686 -- project/mt7686_hdk/apps/iot_sdk_demo
AW7698 -- project/aw7698_evk/apps/iot_sdk_demo
MT5932 -- project/mt5932_hdk/apps/iot_sdk_demo
