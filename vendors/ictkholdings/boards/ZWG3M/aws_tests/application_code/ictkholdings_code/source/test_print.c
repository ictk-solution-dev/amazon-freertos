
#include "atci.h"
#include "atci_main.h"
#include "atci_adapter.h"

#include <string.h>
#include <stdio.h>
#include "syslog.h"


#include "FreeRTOS.h"
#include "task.h"
#include "timers.h"
#include "stack_macros.h"


void test_print(char *log)
{
      atci_send_data(log, strlen(log));
}



