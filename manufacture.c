#include <stdio.h>  
#include <stdlib.h>  
#include <string.h>  
#include <ctype.h>  
#include <string.h>  
#include <unistd.h>
#include <fcntl.h>  
#include <getopt.h>  
#include <errno.h>  
#include <sys/ioctl.h>
#include <pthread.h>
#include <linux/watchdog.h>  
#include <mtd/mtd-user.h>
#include <mntent.h>
#include <libgen.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdint.h>

#include "uart.h"
#include "manufacture.h"
#include "mac.h"
#include "utils.h"

static int thread_wdt = 0;
static char macbuff[20] = {0};
static char s_buff[128] = {0};
static int board_status = 0;
const char *mount_path = "/proc/mounts";

#define DDR_TEST_SIZE		50//Mega Bytes
#define FLASH_TEST_SIZE		100//Mega Bytes

//#define IPERF_SPEED_TEST
#define IPERF3_SERVER_ADDR		"192.168.0.174"

struct f_size
{
	long blocks;
	long avail; 
};

typedef struct _mountinfo 
{
	FILE *fp;
	char devname[80];
	char mountdir[80];
	char fstype[12];
	struct f_size size;
} MOUNTP;

MOUNTP *dfopen(void)
{
	MOUNTP *MP;

	MP = (MOUNTP *)malloc(sizeof(MOUNTP));
	if(!(MP->fp = fopen(mount_path, "r")))
	{
		return NULL;
	}
	else
		return MP;
}

MOUNTP *dfget(MOUNTP *MP, char *path)
{
	char buf[256];
	char *bname;
	char null[16];
	struct statfs lstatfs;
	struct stat lstat; 
	int is_root = 0;

	while(fgets(buf, 255, MP->fp))
	{
		is_root = 0;
		sscanf(buf, "%s%s%s", MP->devname, MP->mountdir, MP->fstype);
		if (strcmp(MP->mountdir, path) == 0)
			is_root = 1;
		if (stat(MP->devname, &lstat) == 0 || is_root)
		{
			if (strstr(buf, MP->mountdir) && S_ISBLK(lstat.st_mode) || is_root)
			{
				statfs(MP->mountdir, &lstatfs);
				MP->size.blocks = lstatfs.f_blocks * (lstatfs.f_bsize/1024); 
				MP->size.avail  = lstatfs.f_bavail * (lstatfs.f_bsize/1024); 
				return MP;
			}
		}
	}
	
    rewind(MP->fp);
    return NULL;
}

int dfclose(MOUNTP *MP)
{
    fclose(MP->fp);
}

int flash_test(int Mbyte)
{
	int ret = -1;
	long space;
	char *test_root = "/home/root/testsource";
	char cmd[100] = {0};

	printf("flash_test %dMbyte\n", Mbyte);

	MOUNTP *MP;
	if ((MP = dfopen()) == NULL)
	{
		perror("error");
		return 1;
	}

	if (!dfget(MP, "/")) {
		printf("fail disk space\n");
		dfclose(MP);
		return -1;
	}

	printf("%-14s%-20s%10lu%10lu\n", MP->mountdir, MP->devname, 
						MP->size.blocks,
						MP->size.avail);

	if ((Mbyte * 0x100000) > (MP->size.avail * 1024)) {
		printf("fail memory size\n");
//		return -1;
	}
	
	printf("========== rootfs test =============\n");
	//write test	
	ret = dd_write("/dev/urandom", 0, test_root, 0, 1024 * 1024 * Mbyte);
	if (ret < 0) {
		printf("fail dd_write\n");
		dfclose(MP);
		return -1;
	}

	//read test
	ret = dd_write(test_root, 0, "/dev/null", 0, 1024 * 1024 * Mbyte);
	if (ret < 0) {
		printf("fail GetAvailableSpace\n");
		dfclose(MP);
		return -1;
	}

	//remove test root file
	sprintf(cmd, "rm -rf %s", test_root);
	ret = system(cmd);
	if (!ret)
		printf("flash %s file remove success\n", test_root);

	printf("%-14s%-20s%10lu%10lu\n", MP->mountdir, MP->devname, 
						MP->size.blocks,
						MP->size.avail);

	dfclose(MP);
	
	return 0;
}

void *wdt_thread(void *unused)
{
	int fd;
	int interval;
	int bootstatus;
	char *dev;
	int led_status = 0;

	while (thread_wdt) {
		if (led_status) {
			led_status = 0;
		} else {
			led_status = 1;
		}
		Set_Led(WDI, led_status);
		sleep(1);
		//fprintf(stdout, "Kicking...\n");
	}

	write(fd, "V", 1);  

	close(fd);  
	return NULL;
}

char *mac_menu(char *eth)
{
	int cnt = 0;
	char c, ascii;
	
	printf("===============================\n");
	printf("       MAC ADDRESS(%s)\n", eth);
	printf("===============================\n");
	printf("\n");
	printf("  input mac address : ");

	while (1) {
		c = getchar();
		//printf("0x%02x\n", c);
		if (0x0a == c)
			break;
		else
			ascii = c;

		macbuff[cnt] = c;
		cnt++;
	}
	printf("\nbuff = %s\n", macbuff);
	printf("\n");

	return &macbuff[0];
}

void save_env(void)
{
	char cmd[128];
	char mac[64];
	char *file_name = "env_list";

	memset(mac, 0, sizeof(mac));
	memset(cmd, 0, sizeof(cmd));
	get_macaddr("eth0", mac);
	sprintf(cmd, "touch /mnt/tmp/%s", mac); 
	system(cmd);

	memset(cmd, 0, sizeof(cmd));
	get_macaddr("eth1", mac);
	sprintf(cmd, "touch /mnt/tmp/%s", mac); 
	system(cmd);
	
	memset(cmd, 0, sizeof(cmd));
	get_macaddr("wlan0", mac);
	sprintf(cmd, "touch /mnt/tmp/%s", mac); 
	system(cmd);

	memset(cmd, 0, sizeof(cmd));
	sprintf(cmd, "ls /mnt/tmp > /mnt/tmp/%s.txt", file_name); 
	system(cmd);

	sync();
/*
	memset(cmd, 0, sizeof(cmd));
	system("chmod 777 /mnt/tmp/*.txt");
	sprintf(cmd, "lsz /mnt/tmp/%s.txt", file_name);	//파일명에 맥과 시리얼 표시
	printf("%s",cmd);
	system(cmd);	
*/
}

void send_serial(void)
{
	char cmd[128];
	char mac[64];
	char *file_name = "env_list";

	memset(cmd, 0, sizeof(cmd));
	system("chmod 777 /mnt/tmp/*.txt");
	sprintf(cmd, "lsz /mnt/tmp/%s.txt", file_name);	//파일명에 맥과 시리얼 표시
	printf("%s",cmd);
	system(cmd);		
}

unsigned long simple_strtoul(char *cp, char **endp,unsigned int base)
{
	unsigned long result = 0,value;

	if (*cp == '0') {
		cp++;
		if ((*cp == 'x') && isxdigit(cp[1])) {
			base = 16;
			cp++;
		}
		if (!base) {
		    base = 8;
		}
	}
	
	if (!base) {
		base = 10;
	}
	while (isxdigit(*cp) && (value = isdigit(*cp) ? *cp-'0' : (islower(*cp)
		? toupper(*cp) : *cp)-'A'+10) < base) {
		result = result*base + value;
		cp++;
	}
	if (endp)
		*endp = (char *)cp;
	return result;
}

void input_serial(void)
{
	int ret1=0,ret2=0;
	char cmd[128];
	char s_numb1[10],s_numb2[10],s_numb3[20];
	char file_name[64]=" ";

	system("rm -rf /mnt/tmp/*");

	printf("input date (yymmdd ex:200916) :");
	while(ret1 <= 0){
		scanf("%s", s_numb3);
		ret1 = simple_strtoul(s_numb3, NULL, 10);
		printf(" date = %06d\n",ret1);
	}

	printf("input model number :");

	scanf("%s", s_numb1);
	printf("model number = %s\n",s_numb1);

	printf("input serial number :");
	while(ret2 <= 0){
		scanf("%s", s_numb2);
		ret2 = simple_strtoul(s_numb2, NULL, 10);
		printf("serial number = %04d\n",ret2);
	}
	printf("\n");
	sprintf(file_name,"MVTECH%06d%s%04d",ret1,s_numb1,ret2); 
	printf(" *** %s ***\n",file_name);

	sprintf(s_buff,"%s",file_name);
	sprintf(cmd,"touch /mnt/tmp/%s", file_name); 
	system(cmd);

	board_status = 1;
	save_env();
}

int send_OffsetDbg(void)
{
	char cmd[128] = {0};
	char *file_name = "/mnt/OffsetDbg.txt";
	FILE *fp = NULL;
	
	fp = fopen("/mnt/OffsetDbg.txt", "rt");
	if (!fp) {
		printf("OffsetDbg file Not Found\n");
		return -1;
	}
	fclose(fp);
	
	memset(cmd, 0, sizeof(cmd));
	system("chmod 777 /mnt/*");
	sprintf(cmd, "lsz %s", file_name);	//파일명에 맥과 시리얼 표시
	printf("%s",cmd);
	system(cmd);

	return 0;
}

int network_test(char *iface)
{
	int i;
	char  pszCommand[100] = {0};
	FILE        *fp = NULL;
	size_t      readSize = 0;
	char        pszBuff[1024] = {0};
	char strGateway[32] = {0};
	char ipaddr[18] = {0};
	char ap_mac[18] = {0};
	char rssi[18] = {0};
	int ret;
	char *str = "100% packet loss";

	system("killall udhcpc");
	system("killall wpa_supplicant");
	sleep(1);
	
	if (!strncmp(iface, "eth", 3)) {
		memset(pszCommand, 0, sizeof(pszCommand));
		sprintf(pszCommand, "ifconfig %s up", iface);
		system(pszCommand);
		
		sleep(4);

		if (!Get_NetworkCarrier(iface))
			return -1;	
	} else if (!strncmp(iface, "wlan0", 5)) {
		memset(pszCommand, 0, sizeof(pszCommand));
		sprintf(pszCommand, "ifconfig %s up", iface);
		system(pszCommand);
		
#if 1
		memset(pszCommand, 0, sizeof(pszCommand));
		sprintf(pszCommand, "wpa_passphrase jskim5G 12345abcd > /etc/wpa_supplicant_test.conf");
		system(pszCommand);
		sleep(1);		
#endif
		memset(pszCommand, 0, sizeof(pszCommand));
		//2018.04.24
		sprintf(pszCommand, "wpa_supplicant -B -Dwext -iwlan0 -c /etc/wpa_supplicant_test.conf");
		//sprintf(pszCommand, "wpa_supplicant -B -Dnl80211 -iwlan0 -c /etc/wpa_supplicant/wpa_supplicant.conf");
		system(pszCommand);
		sleep(1);

		//system("ifconfig wlan0");

		//iw wlan0 station get 40:b0:fa:c1:75:41
	}

	printf("start udhcpc\n");
	memset(pszCommand, 0, sizeof(pszCommand));
	sprintf(pszCommand, "udhcpc -i %s", iface);
	system(pszCommand);
	
	ret = Get_IpAddr(iface, ipaddr);
	if (ret < 0) {
		printf("udhcpc Fail\n");
		return -1;
	}

	////////////  ping test  //////////////
	if (GetGateway(strGateway) < 0) {
		printf("GetGateway Fail\n");
		return -1;
	}
	
	printf("gateway = %s\n", strGateway);
	memset(pszCommand, 0, sizeof(pszCommand));
	sprintf(pszCommand, "ping -c 5 %s -I %s", strGateway, iface);
	
	// excute command
	fp = popen(pszCommand, "r");
	if (!fp) {
        printf("error [%d:%s]\n", errno, strerror(errno));
        return -1;
	}

    // read the result
	readSize = fread((void*)pszBuff, sizeof(char), 1024-1, fp);
	// print result
	printf("%s\n", pszBuff);
	
	char* ptr = strstr(pszBuff, str);
	if (readSize == 0 || ptr != NULL) {
		printf("PING TEST error \n");
		return -1;
	} else
		printf("PING TEST SUCCESS ret = %ld\n", readSize);

	pclose(fp);
	fp = NULL;
	pszBuff[readSize]=0;

#ifdef IPERF_SPEED_TEST//ethernet speed test
	sleep(1);

	memset(pszCommand, 0, sizeof(pszCommand));
	//iperf3 -c <목적지 주소> -B <자신의 주소>
	sprintf(pszCommand, "iperf3 -c %s -B %s", IPERF3_SERVER_ADDR, ipaddr);
	printf("%s\n", pszCommand);
	system(pszCommand);
#endif

#if 0
	memset(pszCommand, 0, sizeof(pszCommand));
	sprintf(pszCommand, "ifconfig %s down", iface);
	system(pszCommand);

	if (!strncmp(iface, "wlan0", 5)) {
		system("killall wpa_supplicant");
	}
#endif

	printf("\n NETWORK (%s) TEST SUCCESS\n\n", iface);

	//wlan rssi
	if (!strncmp(iface, "wlan0", 5)) {
		
		memset(pszCommand, 0, sizeof(pszCommand));
		sprintf(pszCommand, "iwconfig %s", iface);

		// excute command
		fp = popen(pszCommand, "r");
		if (!fp) {
			printf("error [%d:%s]\n", errno, strerror(errno));
			return -1;
		}
		
		// read the result
		memset(pszBuff, 0, sizeof(pszBuff));
		readSize = fread((void*)pszBuff, sizeof(char), 1024-1, fp);
		// print result
		printf("%s\n", pszBuff);

		ptr = NULL;
		ptr = strstr(pszBuff, "Access Point: ");
		if (ptr != NULL) {
			printf("Access Point: Found OK   %p\n", ptr);
			memcpy(ap_mac, ptr + 14, 17);
			printf("%s\n", ap_mac);
		} else {
			printf("Access Point: Found FAIL %p\n", ptr);
			return -1;
		}

		pclose(fp);
		fp = NULL;
		
		//iw wlan0 station get 40:b0:fa:c1:75:41

		memset(pszCommand, 0, sizeof(pszCommand));
		sprintf(pszCommand, "iw wlan0 station get %s", ap_mac);

		for (i = 0; i < 10; i++) {
			// excute command
			fp = popen(pszCommand, "r");
			if (!fp) {
				printf("error [%d:%s]\n", errno, strerror(errno));
				return -1;
			}

			// read the result
			memset(pszBuff, 0, sizeof(pszBuff));
			readSize = fread((void*)pszBuff, sizeof(char), 1024-1, fp);
			// print result
			printf("%s\n", pszBuff);
#if 0
			ptr = NULL;
			ptr = strstr(pszBuff, "signal:");
			if (ptr != NULL) {
				printf("signal: Found OK   %p\n", ptr);
				memcpy(rssi, ptr + 10, 9);
				printf("%s\n", rssi);
			} else {
				printf("signal: Found FAIL %p\n", ptr);
				return -1;
			}
#endif
			pclose(fp);
			fp = NULL;
		}
	}
	
	memset(pszCommand, 0, sizeof(pszCommand));
	sprintf(pszCommand, "ifconfig %s down", iface);
	printf("%s\n", pszCommand);
	system(pszCommand);
	return 0;
}

int LED_Test(void)
{
	int i;
	
	for (i = 0; i < 3; i++) {		
		Set_Led(WIFI_LED1, 0);
		Set_Led(WIFI_LED2, 0);
		Set_Led(STATUS_LED1, 0);
		Set_Led(STATUS_LED2, 0);
		Set_Led(PWR_LED1, 0);
		Set_Led(PWR_LED2, 0);
		usleep(500 * 1000);

		Set_Led(WIFI_LED1, 1);
		Set_Led(WIFI_LED2, 0);
		Set_Led(STATUS_LED1, 1);
		Set_Led(STATUS_LED2, 0);
		Set_Led(PWR_LED1, 1);
		Set_Led(PWR_LED2, 0);
		usleep(500 * 1000);
		
		Set_Led(WIFI_LED1, 0);
		Set_Led(WIFI_LED2, 1);
		Set_Led(STATUS_LED1, 0);
		Set_Led(STATUS_LED2, 1);
		Set_Led(PWR_LED1, 0);
		Set_Led(PWR_LED2, 1);
		usleep(500 * 1000);

		Set_Led(WIFI_LED1, 0);
		Set_Led(WIFI_LED2, 0);
		Set_Led(STATUS_LED1, 0);
		Set_Led(STATUS_LED2, 0);
		Set_Led(PWR_LED1, 0);
		Set_Led(PWR_LED2, 0);
		usleep(500 * 1000);

	}
#if 0
	for (i = 0; i < 4; i++) {		
		Fill_RAM(0xff);
		usleep(500 * 1000);
		Fill_RAM(0x0);
		usleep(500 * 1000);
	}
#endif
}

unsigned char calc_checksum (unsigned char *start_addr, unsigned int len)
{
	unsigned char checksum = 0;
	for (; len > 0; len--, start_addr++)
	{
		checksum += *start_addr;
	}
	return (checksum);
}

int is_mounted (char *dev_path)
{
	FILE * mtab = NULL;
	struct mntent * part = NULL;
	int is_mounted = 0;

	if (( mtab = setmntent ("/etc/mtab", "r")) != NULL) {
		while (( part = getmntent ( mtab)) != NULL) {
			if (( part->mnt_fsname != NULL) 
				&& (strcmp(part->mnt_fsname, dev_path)) == 0) {
				is_mounted = 1;
			}
		}
		endmntent(mtab);
	}

	return is_mounted;
}

char vib_menu(void)
{
	int cnt = 0;
	char c, ascii;
	
	while (1) {
		system("clear");
		printf("===============================\n");
		printf("	   VIBRATION TEST v2.0\n");
		printf("===============================\n");
		printf("\n");
		printf("  select : ");
		
		c = getchar();
		getchar();
		//printf("0x%02x\n", c);
		if (0x0a == c)
			break;
		else
			ascii = c;

		if (c == '1') {
			printf("select 1\n");
			getchar();
		} else if (c == '2') {
			printf("select 2\n");
			getchar();
		} else if (c == 'x') {
			printf("select x\n");
			getchar();
			break;
		}
		cnt++;
	}
	printf("\n\n");

	return ascii;
}


char print_MainMenu(void)
{
	char c, ascii = '@';

	system("clear");
	printf("===============================\n");
	printf("           M E N U\n");
	printf("===============================\n");
	printf("\n");
	printf("   1. memory test\n");
	printf("   2. emmc test\n");
	printf("   3. led test\n");
	printf("   4. ethernet test(eth0)\n");
	printf("   5. ethernet test(eth1)\n");
	printf("   6. wifi     test(wlan0) \n");
	printf("   7. write mac address(eth0)\n");
	printf("   8. write mac address(eth1) \n");
	printf("   9. show mac address\n");
	printf("===============================\n");
	printf("   a. analog test \n");	
	printf("   0. serial input start\n");
	printf("   s. send serial number\n");
	printf("   d. remove serial number \n");	
	printf("   f. spi flash write \n");		
	printf("   r. reboot\n");
	printf("   x. exit\n");
	printf("\n");
	printf("===============================\n");
	printf("  select : ");
	
	while (1) {	   
		c = getchar();
		//printf("0x%02x\n", c);
		if (0x0a == c)
			break;
		else
			ascii = c;
	}

	printf("\n\n");

	return ascii;
}

int main(int argc, char **argv)  
{
	char c;
	int ret;
	pthread_t thid;
	char mac_addr[18];

	//wlan0 pwr
//	usleep(100000);
//	system("insmod /lib/firmware/wlan.ko");
//	usleep(100000);
//	system("ifconfig wlan0 up");

	thread_wdt = 1;
//	pthread_create(&thid, NULL, wdt_thread, NULL);

	//mnt/tmp
	system("mkdir -p /mnt/tmp");
	//// wpa_supplicant.conf
	Get_MacAddr("wlan0", mac_addr);
//	Create_wpafile("ureadythings", mac_addr, "b5638bdddfc77559575bb556bde0eeb9");

	while (1) {
		c = print_MainMenu();
		if (c == '1') {
			printf("  select 1\n");
			int Mbytes = DDR_TEST_SIZE;
			char size[10] = {0};
			char *argv[4] = {"memseter", size, "1", "\0"};
			sprintf(size, "%dM", Mbytes);
			ret = memseter(3, argv);
			if (ret < 0) {
				printf("\n	Memory TEST FAIL\n");
				printf("\n	press enter key");
				getchar();
				continue;
			}

			printf("\n	press enter key");
			getchar();
		} else if (c == '2') {
			printf("  select 2\n");
			flash_test(FLASH_TEST_SIZE);
			printf("\n  press enter key");
			getchar();
		} else if (c == '3') {
			printf("  select 3\n");
			LED_Test();
			printf("\n  press enter key");
			getchar();
		} else if (c == '4') {
			printf("  select 4\n");
			printf("\n  Please Plug the Cable\n");
			printf("\n  press enter key");
			getchar();
			ret = network_test("eth0");
			if (ret < 0) {
				printf("\n network(eth0) test fail\n\n");
				printf("\n	press enter key");
				getchar();
				continue;
			} else
				printf("\n network(eth0) test success\n\n");

			//printf("\n  Lan Cable 변경 하세요.\n");
			printf("\n  press enter key");
			getchar();
		} else if (c == '5') {
			printf("  select 5\n");
			printf("\n  Please Plug the Cable\n");
			printf("\n  press enter key");
			ret = network_test("eth1");
			if (ret < 0) {
				printf("\n network(eth1) test fail\n\n");
				printf("\n	press enter key");
				getchar();
				continue;
			} else
				printf("\n network(eth1) test success\n\n");
			//ret = network_test("eth0", "192.168.0.1");
			//if (ret < 0)
			//	printf("ping test fail\n");
			printf("\n	press enter key");
			getchar();
		} else if (c == '6') {
			ret = network_test("wlan0");
			if (ret < 0) {
				printf("\n network(wlan0) test fail\n\n");
				printf("\n	press enter key");
				getchar();
				continue;
			} else
				printf("\n network(wlan0) test success\n\n");
			printf("\n	press enter key");
			getchar();
		} else if (c == '7') {
			printf("  select 7\n");
			mac_setting1("eth0", mac_menu("eth0"));
		} else if (c == '8') {
			printf("  select 8\n");
			mac_setting2("eth1", mac_menu("eth1"));
		} else if (c == '9') {
			printf("  select 9\n");
			display_macaddr("eth0");
			display_macaddr("eth1");
			display_macaddr("wlan0");
			printf("\n  press enter key");
			getchar();
		} else if (c == '0') {
			printf("  select 0\n");
			input_serial();
			printf("\n  press enter key");
			getchar();
			getchar();
		}  else if (c == 'a') {
			printf("  select a\n");	
			//getchar();
			system("/home/root/utils/calibrator");
		} else if (c == 'b') {
			printf("  select b\n");
			printf("\n  press enter key");
			getchar();
		} else if (c == 't') {
			printf("  select t\n");			
			system("./dcalibrator");
		} else if (c == 'f') {
			system("echo 0 > /sys/class/leds/fpga_prog_b/brightness");
//			system("modprobe spi-nor");
//			system("modprobe m25p80");
			printf("  select f\n");
			fpga_upgrade("/home/root/utils/fpga.bin");
			getchar();
			system("echo 1 > /sys/class/leds/fpga_prog_b/brightness");
//			system("rmmod m25p80");			
//			system("rmmod spi-nor");			
		} else if (c == 'r') {
			sync();
			system("reboot -f");
		} else if (c == 'd') {
			system("rm -rf /mnt/tmp/env_list.txt");
			system("rm -rf /mnt/tmp/MVTECH*");
			sync();
		} else if (c == 's') {
			send_serial();
		} else if (c == 'v') {
			printf("  select v\n");
			system("./vcalibrator");
		} else if (c == 'i') {
			//system("./iolink_test");
			
			printf("###  docker load  #####\n");
			//system("docker load -i /root/mvtech.iolink.os-image_210317.tar");
			system("docker load -i /root/mvtech.iolink.os-image.tar");
			system("docker-compose -f /root/app/docker-compose.yml up");
			printf("\n  press enter key");
			getchar();
		} else if (c == 'x') {
			printf("  exit\n");
			thread_wdt = 0;
			break;
		}
		c = 0;
	}
	
//	pthread_join(thid, NULL);
	exit(1);

	return 0;
} 

