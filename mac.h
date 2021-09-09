#ifndef __MAC_H__
#define __MAC_H__

int display_macaddr(char *iface);
int get_macaddr(char *iface, char *ptr);
int mac_setting(char *cmd, char *macaddress);
int mac_setting1(char *iface, char *macaddress);
int mac_setting2(char *iface, char *macaddress);
int GetGateway(char *pGateway);

#endif //__MAC_H__

