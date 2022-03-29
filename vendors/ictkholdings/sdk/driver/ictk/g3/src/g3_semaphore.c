/* 
  *****************************************************************************
  * @file           : g3_semaphore.c
  * @author         : Department 1, R&D Center, Security SoC Division
  * @version        : V1.0.0
  * @date           : 21-June-2017
  * @brief          : Communication Layer of g3 Library
  *****************************************************************************
  * Copyright (c) 2017 ICTK Co., LTD. All rights reserved.
  */
    
#include <string.h>
#include "puf_if.h"
#include "syslog.h"
#include "g3_semaphore.h"
#include "FreeRTOS.h"
#include "semphr.h"

#ifdef G3_SEMAPHORE

static SemaphoreHandle_t g3_mutex;

void g3_mutex_new()
{
  if(sys_mutex_new(&g3_mutex) != 0)
    printf("g3_mutex_new failed!!\n");
}

void g3_mutex_lock()
{
  sys_mutex_lock(&g3_mutex);
}

void g3_mutex_unlock()
{
  sys_mutex_unlock(&g3_mutex);
}

void g3_mutex_delete()
{
  sys_mutex_free(&g3_mutex);
}
#endif
