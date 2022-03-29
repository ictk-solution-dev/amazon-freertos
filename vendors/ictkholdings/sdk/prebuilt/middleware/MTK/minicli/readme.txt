Minicli module usage guide

Brief: 
	This module is used by the customer for cli input/output operation.

Usage:
	In project, enable MTK_MINICLI_ENABLE=y in feature.mk
	GCC:  Library in the "prebuilt/middleware/MTK/minicli/lib" floder.
	libminicli.a

	KEIL: Library in the "prebuilt/middleware/MTK/minicli/lib" floder.
	libminicli_CM4_Keil.lib

	IAR: Library in the "prebuilt/middleware/MTK/minicli/lib" folder.
	libminicli_CM4_IAR.a

Dependency: 
	It is dependent on different lib which project you use.

Notice: 
	None

Relative doc: 
	middleware/MTK/minicli/cli.h

Example project:
	MT7682 -- project/mt7682_hdk/apps/minicli
	MT7686 -- project/mt7686_hdk/apps/minicli
	MT7687 -- project/mt7687_hdk/apps/minicli
	MT7697 -- project/mt7697_hdk/apps/minicli
