#ifndef __MANUFACTURE_H__
#define __MANUFACTURE_H__

#define DEBUG_PRINTF		1
#define DEBUG_SYSLOG
#ifdef DEBUG_SYSLOG
#define sys_printf(fmt,args...) { if (DEBUG_PRINTF)		\
									printf (fmt,## args); \
								syslog (LOG_NOTICE, fmt,## args); }
#else
#define sys_printf
#endif

#define WATCHDOGDEV		"/dev/watchdog"

#define WIFI_LED1	"wifi_led1"	//Green
#define WIFI_LED2	"wifi_led2"	//Red
#define STATUS_LED1	"cpu_led1"
#define STATUS_LED2	"cpu_led2"	//status
#define PWR_LED1	"pwr_led1"
#define PWR_LED2	"pwr_led2"	//pwr
#define WDI		"wdi"

#endif //__MANUFACTURE_H__

