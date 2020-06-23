

#include "memory_attribute.h"

#include <lwipopts.h>

ATTR_ZIDATA_IN_TCM char ram_heap[ MEM_SIZE ]    @0x04009254;
uint32_t trash                                  @(0x04009254+MEM_SIZE);         
