#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "ictk_util.h"

int hexstr2buf(void *dest, char *src)
  {
  unsigned char *byte;
  char *pvalue;

  int pos = 0;
  int length = 0;

  pvalue = src;

  while (*pvalue != NULL)
  {
          pvalue++;
          length++;
  }

  byte = (unsigned char*)malloc(length);

  for (int i = 0; i < length / 2; i++)
  {
          sscanf(src + pos, "%2hhX", (byte + i));
          pos += 2;
  }
  
  memcpy((unsigned char*)dest, byte, length/2);
  free(byte);

  return length/2;
}

int str2buf(void *dest, char *src)
{
  unsigned char *byte;
  char *pvalue;

  int length = 0;

  pvalue = src;
  while (*pvalue != NULL)
  {
    pvalue++;
    length++;
  }
  byte = (unsigned char*)malloc(length);

  for (int i = 0; i < length; i++)
    *(byte+i) = *(src+i);

  memcpy((unsigned char*)dest, byte, length);
  free(byte);

  return length;
}