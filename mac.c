#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>   //ifreq
#include <unistd.h>   //close
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>

#define BUFSIZE 8192
static char gateway[255] = {0};

struct route_info {
    struct in_addr dstAddr;
    struct in_addr srcAddr;
    struct in_addr gateWay;
    char ifName[IF_NAMESIZE];
};

int readNlSock(int sockFd, char *bufPtr, int seqNum, int pId)
{
	struct nlmsghdr *nlHdr;
	int readLen = 0, msgLen = 0;

	do {
    /* Recieve response from the kernel */
        if ((readLen = recv(sockFd, bufPtr, BUFSIZE - msgLen, 0)) < 0) {
            perror("SOCK READ: ");
            return -1;
        }

        nlHdr = (struct nlmsghdr *) bufPtr;

    /* Check if the header is valid */
        if ((NLMSG_OK(nlHdr, readLen) == 0)
            || (nlHdr->nlmsg_type == NLMSG_ERROR)) {
            perror("Error in recieved packet");
            return -1;
        }

    /* Check if the its the last message */
        if (nlHdr->nlmsg_type == NLMSG_DONE) {
            break;
        } else {
    /* Else move the pointer to buffer appropriately */
            bufPtr += readLen;
            msgLen += readLen;
        }

    /* Check if its a multi part message */
        if ((nlHdr->nlmsg_flags & NLM_F_MULTI) == 0) {
           /* return if its not */
            break;
        }
    } while ((nlHdr->nlmsg_seq != seqNum) || (nlHdr->nlmsg_pid != pId));
    return msgLen;
}
/* For printing the routes. */
void printRoute(struct route_info *rtInfo)
{
    char tempBuf[512];

/* Print Destination address */
    if (rtInfo->dstAddr.s_addr != 0)
        strcpy(tempBuf,  inet_ntoa(rtInfo->dstAddr));
    else
        sprintf(tempBuf, "*.*.*.*\t");
    fprintf(stdout, "%s\t", tempBuf);

/* Print Gateway address */
    if (rtInfo->gateWay.s_addr != 0)
        strcpy(tempBuf, (char *) inet_ntoa(rtInfo->gateWay));
    else
        sprintf(tempBuf, "*.*.*.*\t");
    fprintf(stdout, "%s\t", tempBuf);

    /* Print Interface Name*/
    fprintf(stdout, "%s\t", rtInfo->ifName);

    /* Print Source address */
    if (rtInfo->srcAddr.s_addr != 0)
        strcpy(tempBuf, inet_ntoa(rtInfo->srcAddr));
    else
        sprintf(tempBuf, "*.*.*.*\t");
    fprintf(stdout, "%s\n", tempBuf);
}

void printGateway()
{
    printf("%s  %ld\n", gateway, strlen(gateway));
}
/* For parsing the route info returned */
void parseRoutes(struct nlmsghdr *nlHdr, struct route_info *rtInfo)
{
    struct rtmsg *rtMsg;
    struct rtattr *rtAttr;
    int rtLen;

    rtMsg = (struct rtmsg *) NLMSG_DATA(nlHdr);

/* If the route is not for AF_INET or does not belong to main routing table
then return. */
    if ((rtMsg->rtm_family != AF_INET) || (rtMsg->rtm_table != RT_TABLE_MAIN))
        return;

/* get the rtattr field */
    rtAttr = (struct rtattr *) RTM_RTA(rtMsg);
    rtLen = RTM_PAYLOAD(nlHdr);
    for (; RTA_OK(rtAttr, rtLen); rtAttr = RTA_NEXT(rtAttr, rtLen)) {
        switch (rtAttr->rta_type) {
        case RTA_OIF:
            if_indextoname(*(int *) RTA_DATA(rtAttr), rtInfo->ifName);
            break;
        case RTA_GATEWAY:
            rtInfo->gateWay.s_addr= *(u_int *) RTA_DATA(rtAttr);
            break;
        case RTA_PREFSRC:
            rtInfo->srcAddr.s_addr= *(u_int *) RTA_DATA(rtAttr);
            break;
        case RTA_DST:
            rtInfo->dstAddr .s_addr= *(u_int *) RTA_DATA(rtAttr);
            break;
        }
    }
    //printf("%s\n", inet_ntoa(rtInfo->dstAddr));

    if (rtInfo->dstAddr.s_addr == 0)
        sprintf(gateway, "%s", (char *) inet_ntoa(rtInfo->gateWay));
    //printRoute(rtInfo);

    return;
}


int GetGateway(char *pGateway)
{
	struct nlmsghdr *nlMsg;
	struct rtmsg *rtMsg;
	struct route_info *rtInfo;
	char msgBuf[BUFSIZE];
	int flag = 0;

	int sock, len, msgSeq = 0;

	if (!pGateway)
		return -1;

	/* Create Socket */
	if ((sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0) {
		perror("Socket Creation: ");
		return -1;
	}
	flag = fcntl(sock, F_GETFL, 0);
	fcntl(sock, F_SETFL, flag | O_NONBLOCK);
	
	memset(msgBuf, 0, BUFSIZE);

	/* point the header and the msg structure pointers into the buffer */
	nlMsg = (struct nlmsghdr *) msgBuf;
	rtMsg = (struct rtmsg *) NLMSG_DATA(nlMsg);

	/* Fill in the nlmsg header*/
	nlMsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));  // Length of message.
	nlMsg->nlmsg_type = RTM_GETROUTE;   // Get the routes from kernel routing table .

	nlMsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;    // The message is a request for dump.
	nlMsg->nlmsg_seq = msgSeq++;    // Sequence of the message packet.
	nlMsg->nlmsg_pid = getpid();    // PID of process sending the request.

	/* Send the request */
	if (send(sock, nlMsg, nlMsg->nlmsg_len, 0) < 0) {
		printf("Write To Socket Failed...\n");
		return -1;
	}

	/* Read the response */
	if ((len = readNlSock(sock, msgBuf, msgSeq, getpid())) < 0) {
		printf("Read From Socket Failed...\n");
		return -1;
	}
	/* Parse and print the response */
	rtInfo = (struct route_info *) malloc(sizeof(struct route_info));
	//fprintf(stdout, "Destination\tGateway\tInterface\tSource\n");
	for (; NLMSG_OK(nlMsg, len); nlMsg = NLMSG_NEXT(nlMsg, len)) {
		memset(rtInfo, 0, sizeof(struct route_info));
		parseRoutes(nlMsg, rtInfo);
	}
	free(rtInfo);
	close(sock);

	//printGateway();
	memcpy(pGateway, gateway, strlen(gateway));
	return 0;
}

int set_mac_address(const char *interface, char *mac_address)
{
	struct ifreq ifr;
	int s;

	memset(&ifr, 0x0, sizeof(ifr));
	strcpy(ifr.ifr_name, interface);

	sscanf(mac_address, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
							&ifr.ifr_hwaddr.sa_data[0],
							&ifr.ifr_hwaddr.sa_data[1],
							&ifr.ifr_hwaddr.sa_data[2],
							&ifr.ifr_hwaddr.sa_data[3],
							&ifr.ifr_hwaddr.sa_data[4],
							&ifr.ifr_hwaddr.sa_data[5]
	);
/*
	printf( "Mac addr %02x:%02x:%02x:%02x:%02x:%02x\n",
							ifr.ifr_hwaddr.sa_data[0],
							ifr.ifr_hwaddr.sa_data[1],
							ifr.ifr_hwaddr.sa_data[2],
							ifr.ifr_hwaddr.sa_data[3],
							ifr.ifr_hwaddr.sa_data[4],
							ifr.ifr_hwaddr.sa_data[5]);
*/
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		printf("fail to socket open\n");
		return -1;
	}

	ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
	if (ioctl(s, SIOCSIFHWADDR, &ifr) < 0) {
		printf("fail to set mac address\n");
		close(s);
		return -1;
	}

	close(s);

	return 0;
}

int display_macaddr(char *iface)
{
	int fd;
	struct ifreq ifr;
	//char *iface = "eth0";
	//char *iface = "usb0";
	unsigned char *mac = NULL;
	char cmd[100] = {0};

	memset(cmd, 0, sizeof(cmd));
	sprintf(cmd, "ifconfig %s up", iface);
	system(cmd);

	memset(&ifr, 0, sizeof(ifr));

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);

	if (0 == ioctl(fd, SIOCGIFHWADDR, &ifr)) {
		mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;

		//display mac address
		printf("%s Mac : %02X:%02X:%02X:%02X:%02X:%02X\n" , 
				iface, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	}

	close(fd);

	memset(cmd, 0, sizeof(cmd));
	sprintf(cmd, "ifconfig %s down", iface);
	system(cmd);

	return 0;
}

int get_macaddr(char *iface, char *ptr)
{
	int fd;
	char buf[64];
	struct ifreq ifr;
	unsigned char *mac = NULL;

	memset(&ifr, 0, sizeof(ifr));

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);

	if (0 == ioctl(fd, SIOCGIFHWADDR, &ifr)) {
		mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;

		//display mac address
		sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X\n" , 
				mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		if (ptr)
			memcpy(ptr, buf, ETH_ALEN * 3 - 1);
	}

	close(fd);

	return 0;
}


int mac_setting1(char *iface, char *macaddress)
{
	int i = 0;
	unsigned char mac_data[6] = {0};
	char strMac[10] = {0};
	unsigned int mac0, mac1;
	char pAgrs[50] = {0};
	char cmd[200] = {0};

	if (iface == NULL) {
	    return -1;
	}

	if (strncmp(iface, "eth0", 4) == 0) {
		char *ptr, *p = macaddress;
		unsigned long tmp;
		memcpy(pAgrs, macaddress, strlen(macaddress));

		memset(cmd, 0, sizeof(cmd));
		sprintf(cmd, "ifconfig eth0 down");
		system(cmd);

		if (strlen(macaddress) != 17) {
			printf("invalid mac address %s(%ld)\n\n", macaddress, strlen(macaddress));
			goto exit;
		}

		while (p && (*p) && i < 6) {
			ptr = strchr(p, ':');
			if (ptr)
				*ptr++ = '\0';

			if (strlen(p)) {
				tmp = strtoul(p, (char**)0, 16);
				if (tmp > 0xff)
					goto exit;
				mac_data[i++] = tmp;
			}
			p = ptr;
		}

		for (i = 0; i < 6; i++)
			printf("mac_data[%d] = 0x%02x\n", i, mac_data[i]);

		memset(cmd, 0, sizeof(cmd));
		sprintf(cmd, "printf '\\x%02x\\x%02x' | dd of=/sys/bus/platform/drivers/imx_ocotp/21bc000.ocotp/imx-ocotp0/nvmem bs=4 count=1 skip=35 conv=notrunc ", mac_data[0], mac_data[1]);
//		printf("cmd1 = %s\n", cmd);
		system(cmd);
		
		memset(cmd, 0, sizeof(cmd));
		sprintf(cmd, "printf '\\x%02x\\x%02x\\x%02x\\x%02x' | dd of=/sys/bus/platform/drivers/imx_ocotp/21bc000.ocotp/imx-ocotp0/nvmem bs=4 count=1 skip=34 conv=notrunc ", mac_data[2], mac_data[3], mac_data[4], mac_data[5]);
//		printf("cmd2 = %s\n", cmd);
		system(cmd);
		
		set_mac_address(iface, pAgrs);
		memset(cmd, 0, sizeof(cmd));
		sprintf(cmd, "echo %s > /mnt/tmp/eth0_mac.txt", pAgrs);
		system(cmd);
		sync();
		printf("\n### MAC Write <%s> SUCCESS ###\n\n", pAgrs);
    }

	set_mac_address(iface, pAgrs);

exit:

    printf("\nPress Enter Key");
    getchar();

	return 0;
}

int mac_setting2(char *iface, char *macaddress)
{
    int i = 0, ret;
    unsigned char mac_data[6] = {0};
    char strMac[100] = {0};
    char pAgrs[50] = {0};
	char cmd[100] = {0};

	if (iface == NULL) {
		return -1;
	}

    if (strncmp(iface, "eth1", 4) == 0) {
		memcpy(pAgrs, macaddress, strlen(macaddress));
		char *ptr, *p = macaddress;
		unsigned long tmp;

		memset(cmd, 0, sizeof(cmd));
		sprintf(cmd, "ifconfig eth1 down");
		system(cmd);

		if (strlen(macaddress) != 17) {
			printf("invalid mac address %s(%ld)\n\n", macaddress, strlen(macaddress));
			goto exit;
		}

		while (p && (*p) && i < 6) {
			ptr = strchr(p, ':');
			if (ptr)
				*ptr++ = '\0';

				if (strlen(p)) {
					tmp = strtoul(p, (char**)0, 16);
				//printf("tmp[%d] = 0x%x\n", i, tmp);
				if (tmp > 0xff)
					goto exit;
				mac_data[i++] = tmp;
			}
			p = ptr;
		}

		for (i = 0; i < 6; i++) {
			//printf("mac_data[%d] = 0x%x\n", i, mac_data[i]);
			memset(strMac, 0, sizeof(strMac));
			sprintf(strMac, "ethtool -E %s magic 0x9500 offset %d value 0x%x", iface, i + 1, mac_data[i]);
			//printf("%s\n", strMac);
			ret = system(strMac);
			if (ret) {
				printf("mac setting fail\n");
				return -1;
			}
		}

		set_mac_address(iface, pAgrs);
		printf("\n### MAC Write <%s> SUCCESS ###\n\n", pAgrs);
	}
exit:
	printf("\nPress Enter Key");
	getchar();

    return 0;
}



