#include <stdio.h>  
#include <stdlib.h>
#include <time.h>  
//#include <iwlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <errno.h>
#include <pthread.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <netinet/in.h> 
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <linux/route.h>
#include <dirent.h>
#include <unistd.h>
#include <linux/unistd.h>
#include <sys/stat.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <linux/module.h>
//#include <iwlib.h>

#include "utils.h"

int Set_Led(char *id, int val)
{
	int ret;
	char cmd[64] = {0};

	sprintf(cmd, "echo %d > /sys/class/leds/%s/brightness", val, id);
	
	ret = system(cmd);
	//printf("cmd %s\n", cmd);
	return ret;
}

int Set_USBEthPower(int val)
{
	int ret;
	char cmd[64] = {0};

	sprintf(cmd, "echo 1 > /sys/class/leds/eth_rst_led/brightness");
	ret = system(cmd);

	memset(cmd, 0, sizeof(cmd));
	sprintf(cmd, "echo %d > /sys/class/leds/eth_en_led/brightness", val);
	
	ret = system(cmd);

	return ret;
}

uint64_t pack754(long double f, unsigned bits, unsigned expbits)
{
	long double fnorm;
	int shift;
	long long sign, exp, significand;
	unsigned significandbits = bits - expbits - 1; // -1 for sign bit

	if (f == 0.0) return 0; // get this special case out of the way

	// check sign and begin normalization
	if (f < 0) { sign = 1; fnorm = -f; }
	else { sign = 0; fnorm = f; }

	// get the normalized form of f and track the exponent
	shift = 0;
	while(fnorm >= 2.0) { fnorm /= 2.0; shift++; }
	while(fnorm < 1.0) { fnorm *= 2.0; shift--; }
	fnorm = fnorm - 1.0;

	// calculate the binary form (non-float) of the significand data
	significand = fnorm * ((1LL<<significandbits) + 0.5f);

	// get the biased exponent
	exp = shift + ((1<<(expbits-1)) - 1); // shift + bias

	// return the final answer
	return (sign<<(bits-1)) | (exp<<(bits-expbits-1)) | significand;
}

long double unpack754(uint64_t i, unsigned bits, unsigned expbits)
{
	long double result;
	long long shift;
	unsigned bias;
	unsigned significandbits = bits - expbits - 1; // -1 for sign bit

	if (i == 0) return 0.0;

	// pull the significand
	result = (i&((1LL<<significandbits)-1)); // mask
	result /= (1LL<<significandbits); // convert back to float
	result += 1.0f; // add the one back on

	// deal with the exponent
	bias = (1<<(expbits-1)) - 1;
	shift = ((i>>significandbits)&((1LL<<expbits)-1)) - bias;
	while(shift > 0) { result *= 2.0; shift--; }
	while(shift < 0) { result /= 2.0; shift++; }

	// sign it
	result *= (i>>(bits-1))&1? -1.0: 1.0;

	return result;
}

long Get_TimeStamp(void)
{
#if 0
	time_t time_now;   
	struct tm *tm ;       

	time(&time_now);
	tm = localtime(&time_now) ;   

	printf(ctime(&time_now)) ;   
	  
	printf("year : %d \n" , tm->tm_year+1900);
	printf("month: %d \n" , tm->tm_mon+1);
	printf("day : %d \n" , tm->tm_mday);
	printf("hour : %d \n" , tm->tm_hour);
	printf("min : %d \n" , tm->tm_min);
	printf("sec : %d \n" , tm->tm_sec);
	printf("wday : %d \n" , tm->tm_wday) ; // 0~6 , day of the week 
	printf("yday : %d \n" , tm->tm_yday) ; // past time from 1, Jan 
#else
	struct timespec tspec;
	clock_gettime(CLOCK_REALTIME, &tspec);
	
	// convert tv_sec & tv_nsec to millisecond
	double time_in_mill = (tspec.tv_sec) * 1000 + (tspec.tv_nsec) / 1000000;
#endif
	return time_in_mill;
}  

unsigned int Get_ProcessID(char *p_processname) {
	DIR *dir_p;
	struct dirent *dir_entry_p;
	char dir_name[40];
	char target_name[252];
	int target_result;
	char exe_link[252];
	int errorcount;
	int result;

	errorcount=0;
	result=0;
	dir_p = opendir("/proc/");
	while(NULL != (dir_entry_p = readdir(dir_p))) {
		if (strspn(dir_entry_p->d_name, "0123456789") == strlen(dir_entry_p->d_name)) {
			strcpy(dir_name, "/proc/");
			strcat(dir_name, dir_entry_p->d_name);
			strcat(dir_name, "/");
			exe_link[0] = 0;
			strcat(exe_link, dir_name);
			strcat(exe_link, "exe");
			target_result = readlink(exe_link, target_name, sizeof(target_name)-1);
			if (target_result > 0) {
				target_name[target_result] = 0;
				if (strstr(target_name, p_processname) != NULL) {
					result = atoi(dir_entry_p->d_name);
					printf("getProcessID(%s) :Found. id = %d\n", p_processname, result);
					closedir(dir_p);
					return result;
				}
			}
		}
	}
	closedir(dir_p);
	printf("getProcessID(%s) : id = 0 (could not find process)\n", p_processname);
	return result;
}

int Create_wpafile(char *ssid, char *id, char *password)
{
	FILE *fp = NULL;

	fp = fopen("/etc/wpa_supplicant.conf", "w");
	//fp = fopen("./wpa_supplicant.conf", "w");
	if (!fp) {
		printf("failed create wpa_supplicant.conf \n");
		return -1;
	}

	fprintf(fp, "ctrl_interface_group=wheel\n");
	fprintf(fp, "eapol_version=1\n");
	fprintf(fp, "ap_scan=1\n");
	fprintf(fp, "fast_reauth=0\n");
	
	// jskim5G AP
	fprintf(fp, "network={\n");
	fprintf(fp, "        ssid=\"jskim5G\"\n");
	fprintf(fp, "        #psk=\"12345abcd\"\n");
	fprintf(fp, "        psk=172088efc195d8f98c0169f1dcd52e2e7e1c8acc55e0fc118669f785a9dcb03e\n");
	fprintf(fp, "}\n");
	fprintf(fp, "\n");
	//jskim5G ap end

	fprintf(fp, "network={\n");
	fprintf(fp, "        ssid=\"%s\"\n", ssid);
	fprintf(fp, "        #proto=RSN\n");
	fprintf(fp, "        key_mgmt=IEEE8021X WPA-EAP\n");
	fprintf(fp, "        identity=\"%s\"\n", id);
//	fprintf(fp, "        password=\"%s\"\n", password);
	fprintf(fp, "        password=hash:%s\n", password);
	fprintf(fp, "        pairwise=CCMP TKIP\n");
	fprintf(fp, "        group=CCMP TKIP WEP104 WEP40\n");
	fprintf(fp, "        phase1=\"peap_outer_success=0\"\n");
	fprintf(fp, "        #peap_outer_success=0\n");
	fprintf(fp, "        phase2=\"auth=MSCHAPV2\"\n");
	fprintf(fp, "        #ca_cert=\"/etc/cert/ca.pem\"\n");
	fprintf(fp, "}\n");
	fprintf(fp, "\n");

	fclose(fp);

	return 0;
}

void Create_wpafile2(char *ssid, char *password)
{
	char* passphrase = "wpa_passphrase %s %s > /etc/wpa_supplicant.conf";
	char  proc[512] = {0};

	if(strlen(password)>=8 && strlen(ssid)>=0) {
		sprintf(proc, passphrase, ssid, password);
		system(proc);
		//read_passwd_en("/etc/wpa_supplicant/wpa_supplicant.conf", passwd_en);
	}	
}

int Get_NetworkCarrier(char *ifname)
{
	int fd;
	char *value;
	char buf[64];
	char dev[32];
	int n, ret = 0;

	sprintf(dev, "/sys/class/net/%s/carrier", ifname);
	if((fd = open(dev, O_RDONLY)) < 0) {
		printf("open failed %s\n", dev);
		return ret;
	} else {
		if(n = read(fd, buf, sizeof(buf)) < 0) {
			close(fd);
			printf("open failed %s\n", dev);
			return ret;
		}
		buf[n-1] = '\0';
		ret = atoi(buf); 
		close(fd);
	}

	return ret;
}
#if 0
int Get_ApMacAddr(char *ifname, char *ap_mac)
{
	int i;
	int sock;
	wireless_config cfg;
	struct iwreq wrq;
	sockaddr    ap_addr;

	/* Open socket to kernel */
	sock = iw_sockets_open();

	if (iw_get_basic_config(sock, ifname, &cfg) < 0) {
		printf("Error iw_get_basic_config. Aborting.\n");
		return -1;
	}

	/* Get AP address */
	if(iw_get_ext(sock, ifname, SIOCGIWAP, &wrq) < 0)
	{
		return -1;
	}

	memcpy(&ap_addr, &(wrq.u.ap_addr), sizeof (sockaddr));

	unsigned char *APaddr = (unsigned char *)wrq.u.ap_addr.sa_data;
	/*
	for(i = 0; i < 6;i++)
	{
		printf("%02x",(int)APaddr[i]);
		if(i != 5)
			printf("%c",':');
		else
			printf("\n");
	}*/

	sprintf(ap_mac, "%02x:%02x:%02x:%02x:%02x:%02x", 
					ap_addr.sa_data[0], ap_addr.sa_data[1], ap_addr.sa_data[2], ap_addr.sa_data[3], ap_addr.sa_data[4], ap_addr.sa_data[5]);

	iw_sockets_close(sock);

	return 0;
}
#endif
int Get_LinkStat(char *ifname)
{
	int fd;
	int ret;
	struct ifreq ifr;
	struct ethtool_value eth;

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (fd < 0) {
		printf("failed socket open  %s\n", ifname);
		return ret;
	}

	bzero(&ifr, sizeof(ifr));
	strcpy(ifr.ifr_name, ifname);
	ifr.ifr_data = (caddr_t) &eth;
	eth.cmd = ETHTOOL_GLINK;

	ret = ioctl(fd, SIOCETHTOOL, &ifr);
	if (fd < 0) {
		printf("failed socket SIOCETHTOOL  %s\n", ifname);
		return ret;
	}
	
	close(fd);

	return (eth.data) ? 1:0;
}

int Get_WlanStat(void)
{
	int fd;
	char *value;
	char buf[PATH_MAX];
	char *dev;
	int n, ret = 0;
	char ipaddr[16] = {0};

	dev = NET_WLAN_STATUS;
	if((fd = open(dev, O_RDONLY)) < 0) {
		printf("open failed %s\n", NET_WLAN_STATUS);
		return ret;
	} else {
		if(n = read(fd, buf, sizeof(buf)) < 0) {
			close(fd);
			printf("open failed %s\n", NET_WLAN_STATUS);
			return ret;
		}
		buf[n-1] = '\0';
		ret = atoi(buf); 
		close(fd);
	}

	return ret;
}

int Get_IpAddr(char *ifname, char *addr)
{
	int fd, ret = -1;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		printf("failed socket open  %s\n", ifname);
		return ret;
	}

	/* I want to get an IPv4 IP address */
	ifr.ifr_addr.sa_family = AF_INET;

	/* I want IP address attached to "eth0" */
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

	ret = ioctl(fd, SIOCGIFADDR, &ifr);
	if (ret < 0) {
		printf("failed socket SIOCGIFADDR  %s\n", ifname);
		close(fd);
		return ret;
	}

	close(fd);

	/* display result */
	//printf("%s\n", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	strcpy(addr, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

	return 0;
}

int Get_MacAddr(char *ifname, char *addr)
{
	struct ifreq ifr;
	char mac[18] = {0};
	
	int sock = socket(AF_INET,SOCK_DGRAM,0);

	// Get the interface IP address
	strcpy( ifr.ifr_name, ifname );
	ifr.ifr_addr.sa_family = AF_INET;

	if (ioctl(sock, SIOCGIFHWADDR, &ifr ) < 0) {
		printf("failed socket SIOCGIFHWADDR  %s\n", ifname);
		return -1;
	}
	
	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
	uint8_t *hwaddr = (uint8_t*)mac;
	sprintf(addr, "%02x%02x%02x%02x%02x%02x", hwaddr[0], hwaddr[1],
			hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
	//printf("The hardware address (SIOCGIFHWADDR) of %s is type %d "
	//		"%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x.\n", ifname,
	//		ifr.ifr_hwaddr.sa_family, hwaddr[0], hwaddr[1],
	//		hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);

	close(sock);
	return 0;
}

int Set_Gateway(const char * defGateway)   
{
	int sockfd;
	struct rtentry route;
	struct sockaddr_in *addr;
	int err = 0;

	// create the socket
	if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		return -1;
	}

	memset(&route, 0, sizeof(route));
	addr = (struct sockaddr_in*) &route.rt_gateway;
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = inet_addr(defGateway);
	addr = (struct sockaddr_in*) &route.rt_dst;
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = inet_addr("0.0.0.0");
	addr = (struct sockaddr_in*) &route.rt_genmask;
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = inet_addr("0.0.0.0");
	route.rt_flags = RTF_UP | RTF_GATEWAY;
	route.rt_metric = 0;
	
	if ((err = ioctl(sockfd, SIOCADDRT, &route)) != 0) {
		printf("SIOCADDRT failed\n");
		return -1;
	}

	return 0;
}

int Set_Network(char *name, char *ipaddr, char *gateway, char *netmask) 
{ 
	int fd; 
	struct ifreq ifreq; 
	struct sockaddr_in sin_ip; 
	struct sockaddr_in *sin; 
	struct sockaddr_in sin_subnet; 

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		printf("Failed to Active Network\n");
		return -1;
	}

#if 1
	//ethernet down
	memset(&ifreq, 0, sizeof(ifreq));
	strcpy(ifreq.ifr_name, name);
	ioctl(fd, SIOCGIFFLAGS, &ifreq);

	ifreq.ifr_flags &= ~(IFF_UP | IFF_RUNNING  );
	ioctl(fd, SIOCSIFFLAGS, &ifreq);
#endif
#if 0
	// To read from interface
	/* ip address */
	if (ioctl(fd, SIOCGIFADDR, &ifreq) == 0) {
		sin = (struct sockaddr_in *)&ifreq.ifr_broadaddr;
		//printf("IP ADDRESS: %s\n", inet_ntoa(sin->sin_addr));

		/* broadcast */
		ioctl(fd, SIOCGIFBRDADDR, &ifreq);
		sin = (struct sockaddr_in *)&ifreq.ifr_broadaddr;
		//printf("BROADCAST: %s\n", inet_ntoa(sin->sin_addr));

		/* netmask */
		ioctl(fd, SIOCGIFNETMASK, &ifreq);
		sin = (struct sockaddr_in *)&ifreq.ifr_broadaddr;
		//printf("NETMASK: %s\n", inet_ntoa(sin->sin_addr));
	}
#endif
	// To set interface
	/* Set up IP address */
	memset(&sin_ip, 0, sizeof(struct sockaddr));
	sin_ip.sin_family = AF_INET;
	inet_aton(ipaddr, &sin_ip.sin_addr);
	memcpy(&ifreq.ifr_addr, &sin_ip, sizeof(struct sockaddr));
	ioctl(fd, SIOCSIFADDR, &ifreq);
#if 0
	/* Set up netmask */
	memset(&sin_subnet, 0, sizeof(struct sockaddr));
	sin_subnet.sin_family = AF_INET;
	inet_aton(netmask, &sin_subnet.sin_addr);
	memcpy(&ifreq.ifr_netmask, &sin_subnet, sizeof(struct sockaddr));
	ioctl(fd, SIOCSIFNETMASK, &ifreq);
#endif
	ioctl(fd, SIOCGIFFLAGS, &ifreq);
	
	//printf("eth0 up----------------link %d\n", link_stat());
	ifreq.ifr_flags |= IFF_UP | IFF_RUNNING;

	ioctl(fd, SIOCSIFFLAGS, &ifreq);

	close(fd); 

	/* Set up gateway */
	if (gateway)
		Set_Gateway(gateway);

	return 0; 
} 

void *load_file(const char *fn, unsigned *_sz)
{
	char *data;
	int sz;
	int fd;

	data = 0;
	fd = open(fn, O_RDONLY);
	if (fd < 0) {
		printf("failed open\n");
		return 0;
	}

	sz = lseek(fd, 0, SEEK_END);
	if (sz < 0) {
		printf("failed open\n");
		goto oops;
	}

	if (lseek(fd, 0, SEEK_SET) != 0)
		goto oops;

	data = (char*) malloc(sz + 1);
	if (data == 0)
		goto oops;

	if (read(fd, data, sz) != sz)
		goto oops;
	close(fd);
	data[sz] = 0;

	if (_sz)
		*_sz = sz;
	return data;

oops:
	close(fd);
	if(data != 0)
		free(data);
	
    return 0;
}

int Load_module(const char *filename, const char *args)
{
	int ret = 0;
	void *module;
	unsigned int size;
	char cmd[16] = {0};
	char buf[16] = {0};

	sprintf(cmd, "lsmod | grep %s", "wlan");
	FILE *fp = popen(cmd, "r");
		
	if (fread (buf, 1, sizeof (buf), fp) > 0) {
		printf("module is loaded\n");
		fclose(fp);
		return 0;
	} else {
		printf("module is unloaded\n");
		fclose(fp);
	}

	module = load_file(filename, &size);
	if (!module) {
		printf("failed load_file\n");
		return -1;
	}

	ret = init_module(module, size, args);
	if (ret < 0) {
		printf("failed init_module\n");
	}

	if (module)
	    free(module);

	return ret;
}

int Remove_module(const char *modname)
{
	int ret = -1;
	int maxtry = 10;

	while (maxtry-- > 0) {
		ret = delete_module(modname, O_NONBLOCK | O_EXCL);
		if (ret < 0 && errno == EAGAIN)
			usleep(500000);
		else
			break;
	}

	if (ret != 0)
		printf("Unable to unload driver module \"%s\": %s\n",
						modname, strerror(errno));
	return ret;
}
#if 0
int Wifi_ReConnect(char *ifname, char* ssid, char* id, char* passwd, int peap_server)
{
	int ret;

	ret = Wifi_Connect(WLAN_ETH, ssid, id, passwd, 0);
	if (ret < 0)	{
		printf("Wifi_Connect fail\n");
		return FAIL;
	}

	sleep(2);

	ret = do_dhcp(WLAN_ETH, 30);
	if (!ret)			
		printf("do_dhcp success\n");
	else {
		Set_Led(WIFI_LED2, 0);
		Set_Led(WIFI_LED1, 1);
	}

	return ret;
}

int Wifi_Connect(char *ifname, char* ssid, char *id, char* passwd, int peap_server)
{
	char* supplicant = "wpa_supplicant -B -i%s -c/etc/wpa_supplicant.conf -Dnl80211";
	char  proc[512] = {0};
	int ret;
	pid_t wpa_pid = 0;

	wpa_pid = Get_ProcessID("wpa_supplicant");
	if (wpa_pid)
		system("killall wpa_supplicant");
	
	usleep(1000 * 1000);

	wpa_pid = Get_ProcessID("wpa_supplicant");
	if (wpa_pid)
		system("killall wpa_supplicant");

	if (peap_server)
		Create_wpafile(ssid, id, passwd);
	else
		Create_wpafile2(ssid, passwd);
	
	memset(proc, 0, sizeof(proc));
	sprintf(proc, supplicant, ifname);
	ret = system(proc);
	if (ret)
		return -1;

	printf("### wifi station mode connect success\n");

	return ret;
}

int Get_ApMacAddr(char *ifname, char *ap_mac)
{
	int i;
	int sock;
	wireless_config cfg;
	struct iwreq wrq;
	sockaddr    ap_addr;

	/* Open socket to kernel */
	sock = iw_sockets_open();

	if (iw_get_basic_config(sock, ifname, &cfg) < 0) {
		printf("Error iw_get_basic_config. Aborting.\n");
		return FAIL;
	}

	/* Get AP address */
	if(iw_get_ext(sock, ifname, SIOCGIWAP, &wrq) < 0)
	{
		return FAIL;
	}

	memcpy(&ap_addr, &(wrq.u.ap_addr), sizeof (sockaddr));

	unsigned char *APaddr = (unsigned char *)wrq.u.ap_addr.sa_data;
	/*
	for(i = 0; i < 6;i++)
	{
		printf("%02x",(int)APaddr[i]);
		if(i != 5)
			printf("%c",':');
		else
			printf("\n");
	}*/

	sprintf(ap_mac, "%02x:%02x:%02x:%02x:%02x:%02x", 
					ap_addr.sa_data[0], ap_addr.sa_data[1], ap_addr.sa_data[2], ap_addr.sa_data[3], ap_addr.sa_data[4], ap_addr.sa_data[5]);

	iw_sockets_close(sock);

	return SUCC;
}

int Get_WlanSSID(char *ifname, char *ssid)
{
	int i;
	wireless_scan_head head;
	wireless_scan *result;
	iwrange range;
	int sock;
	wireless_config cfg;
	struct iwreq		wrq;

	/* Open socket to kernel */
	sock = iw_sockets_open();
#if 0
	/* Get some metadata to use for scanning */
	if (iw_get_range_info(sock, ifname, &range) < 0) {
		printf("Error during iw_get_range_info. Aborting.\n");
		return FAIL; 
	}

	/* Perform the scan */
	if (iw_scan(sock, ifname, range.we_version_compiled, &head) < 0) {
		printf("Error during iw_scan. Aborting.\n");
		return FAIL; 
	}

	/* Traverse the results */
	result = head.result;
	while (NULL != result) {
		printf("%s\n", result->b.essid);
		result = result->next;
	}
#endif
	if (iw_get_basic_config(sock, ifname, &cfg) < 0) {
		printf("Error iw_get_basic_config. Aborting.\n");
		return FAIL; 
	}

	strncpy(ssid, cfg.essid, strlen(cfg.essid));

	iw_sockets_close(sock);

	return SUCC; 
}
#endif

int dd_write(const char *inputfile, long skip, const char *outfile, long seek, long size)
{
	int ret;
	FILE *fin = NULL, *fout = NULL;
	long write_size = size;
	unsigned char *pBuf = NULL;
	long skip_offset = skip;
	long seek_offset = seek;
#define UNIT_CYLINDER	(64*512)

	fin = fopen(inputfile, "rb");
	
	if (!fin) {
		printf("can't open input file:%s : %s\n",
					inputfile, strerror(errno));
		return -1;
	}

	fout = fopen(outfile, "wb");
	if (!fout) {
		printf("can't open output file:%s : %s\n",
					outfile, strerror(errno));
		goto error;
	}

	if (skip_offset != 0) {
		ret = fseek(fin, skip_offset, SEEK_SET);
		if (ret < 0) {
			printf("can't skip: %d to :%s : %s\n", (unsigned int)skip_offset, inputfile, strerror(errno));

			goto error;
		}
	}

	if (seek_offset != 0) {
		ret = fseek(fout, seek_offset, SEEK_SET);
		if (ret < 0) {
			printf("can't seek: %d to :%s : %s\n",
						(unsigned int)seek_offset, outfile, strerror(errno));
			goto error;
		}
	}

	pBuf = (unsigned char *)malloc(UNIT_CYLINDER);
	if(!pBuf)	{
		printf("Buff malloc error!\n");
		goto error;
	}

	printf("==============================================================================\n");
	printf("dd if=%s of=%s skip=%d seek=%d bs=1 size=%d\n", 
		inputfile, outfile, (unsigned int)skip, (unsigned int)seek, (unsigned int)size);

	while (write_size > UNIT_CYLINDER) {

		memset(pBuf, 0, UNIT_CYLINDER);

		ret = fread(pBuf, 1, UNIT_CYLINDER, fin);
		if (ret < UNIT_CYLINDER) {
			printf("fread error:%s :%s \n",
						inputfile, strerror(errno));
			goto error;
		}

		ret = fwrite(pBuf, 1, UNIT_CYLINDER, fout);
		if (ret < UNIT_CYLINDER) {
			printf("fwrite error:%s : %s\n", outfile, strerror(errno));
			goto error;
		}
		
		write_size -= UNIT_CYLINDER;
		printf("\rProgress : %d / %d", (unsigned int)(size-write_size), (unsigned int)size);
	}
	sync();
	
	if(write_size > 0 ) {
		memset(pBuf, 0, UNIT_CYLINDER);
		
		ret = fread(pBuf, 1, write_size, fin);
		if (ret < write_size) {
			printf("fread error:%s :%s \n",
						inputfile, strerror(errno));
			goto error;
		}

		ret = fwrite(pBuf, 1, write_size, fout);
		if (ret < write_size) {
			printf("fwrite error:%s : %s\n", outfile, strerror(errno));
			goto error;
		}
		
		printf("\rProgress : %d / %d", (unsigned int)(size), (unsigned int)size);
	}
	sync();

	printf("\ndd_write complete\n");
//	for( i = 0 ; i < 16 ; i++) {
//		printf("0x%02x ", 	(char)pBuf[write_size-16+i]); 
//	}
	printf("\n");
	free(pBuf);
	if (fout)
		fclose(fout);
	if (fin)
		fclose(fin);

	return 0;

error:	
	if (pBuf)
		free(pBuf);
	if (fout)
		fclose(fout);
	if (fin)
		fclose(fin);

	return -1;

}

char
calculate_checksum (const char *msg, unsigned int length)
{
    int  i;
    char checksum = 0;

    for(i = 0; i < (length - 1); i++)
        checksum = checksum + *(msg + i);

    checksum = (256 - checksum) & 0x7F;
    //DBGMSG(0, ("calculated checksum = 0x%02x\n", checksum));

    return checksum;
}

