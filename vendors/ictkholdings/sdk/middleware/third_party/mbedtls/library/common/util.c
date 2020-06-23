#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "common/util.h"

#ifdef __cplusplus
extern "C" {
#endif

int set_buffer_from_hexstr(void *dest, const char *src)
{
	unsigned char *byte;
	char *pvalue;

	int pos = 0;

	int length = 0;
	
	pvalue = (char*)src;

	while (*pvalue != NULL)
	{
		pvalue++;
		length++;
	}
	//printf("len : %d\n", length);
	 
	byte = (unsigned char*)malloc(length);
	
#if 1
//	printf("set : \r\n");
	for (int i = 0; i < length / 2; i++)
	{
		//sscanf_s(src + pos, "%2hhX", (byte + i));
		sscanf(src + pos, "%2hhX", (byte + i));
		pos += 2;

//		printf("%02X", *(byte + i));
	}
//	printf("\n");

	memcpy((unsigned char*)dest, byte, length);
	free(byte);
#endif

	return length/2;
}

unsigned char HexChar (char c)
{
    if ('0' <= c && c <= '9') return (unsigned char)(c - '0');
    if ('A' <= c && c <= 'F') return (unsigned char)(c - 'A' + 10);
    if ('a' <= c && c <= 'f') return (unsigned char)(c - 'a' + 10);
    return 0xFF;
}

int HexToBin (/*const*/ char* s, unsigned char * buff, int length)
{
    int result;
    if (!s || !buff || length <= 0) return -1;

    for (result = 0; *s; ++result)
    {
        unsigned char msn = HexChar(*s++);
        if (msn == 0xFF) return -1;
        unsigned char lsn = HexChar(*s++);
        if (lsn == 0xFF) return -1;
        unsigned char bin = (msn << 4) + lsn;

        if (length-- <= 0) return -1;
        *buff++ = bin;
    }
    return result;
}
#ifdef __cplusplus
}
#endif


