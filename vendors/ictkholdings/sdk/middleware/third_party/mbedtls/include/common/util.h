#ifndef __ICTK_UTIL_H
#define __ICTK_UTIL_H

/* Includes ------------------------------------------------------------------*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Variables ------------------------------------------------------------------*/

#ifdef __cplusplus
extern "C" {
#endif

/* Defines ------------------------------------------------------------------*/
int set_buffer_from_hexstr(void *dest, const char *src);
int HexToBin (/*const*/ char* s, unsigned char * buff, int length);

#ifdef __cplusplus
}
#endif
#endif /*__ICTK_UTIL_H*/

