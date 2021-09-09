#ifndef __UTILS_H__
#define __UTILS_H__

#ifdef __cplusplus
extern "C" {
#endif

#define NET_WLAN_STATUS		"/sys/class/net/wlan0/carrier"

#define pack754_32(f) (pack754((f), 32, 8))
#define pack754_64(f) (pack754((f), 64, 11))
#define unpack754_32(i) (unpack754((i), 32, 8))
#define unpack754_64(i) (unpack754((i), 64, 11))

int Load_module(const char *filename, const char *args);
int Remove_module(const char *modname);
int Set_Led(char *id, int val);
int Set_USBEthPower(int val);
uint64_t pack754(long double f, unsigned bits, unsigned expbits);
long double unpack754(uint64_t i, unsigned bits, unsigned expbits);
int Load_module(const char *filename, const char *args);
int Remove_module(const char *modname);
int Wifi_ReConnect(char *ifname, char* ssid, char* id, char* passwd, int peap_server);
int Wifi_Connect(char *ifname, char* ssid, char *id, char* passwd, int peap_server);
int Get_LinkStat(char *ifname);
int Create_wpafile(char *ssid, char *id, char *password);
void Create_wpafile2(char *id, char *password);
int Get_IpAddr(char *ifname, char *addr);
int Get_MacAddr(char *ifname, char *addr);
int Get_ApMacAddr(char *ifname, char *ap_mac);
int Get_WlanSSID(char *ifname, char *ssid);
long Get_TimeStamp(void);
int Get_WlanStat(void);
int ping(char *ip_addr);

#ifdef __cplusplus
}
#endif

#endif

