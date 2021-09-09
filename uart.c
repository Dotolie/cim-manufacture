/*
 * Copyright 2014 MVtech Co., Ltd, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termio.h>
#include <unistd.h>
#include <fcntl.h>

#define DEFAULT_RATE			115200;
#define DEFAULT_TX_SIZE			100;
#define DEFAULT_LOOP_COUNT		10;
#define DEFAULT_START_TX_DATA		'A';

static speed_t baudrate_map(unsigned long b)
{
    speed_t retval;

    switch(b)
    {
        case 110:
            retval = B110;
            break;

        case 300:
            retval = B300;
            break;

        case 1200:
            retval = B1200;
            break;

        case 2400:
            retval = B2400;
            break;

        case 4800:
            retval = B4800;
            break;

        case 9600:
            retval = B9600;
            break;

        case 19200:
            retval = B19200;
            break;

        case 38400:
            retval = B38400;
            break;

        case 57600:
            retval = B57600;
            break;

        case 115200:
            retval = B115200;
            break;

#ifdef B230400
        case 230400:
            retval = B230400;
            break;
#endif

#ifdef B460800
        case 460800:
            retval = B460800;
            break;
#endif

#ifdef B500000
        case 500000:
            retval = B500000;
            break;
#endif

#ifdef B576000
        case 576000:
            retval = B576000;
            break;
#endif

#ifdef B921600
        case 921600:
            retval = B921600;
            break;
#endif

#ifdef B1000000
        case 1000000:
            retval = B1000000;
            break;
#endif

#ifdef B1152000
        case 1152000:
            retval = B1152000;
            break;
#endif

#ifdef B1500000
        case 1500000:
            retval = B1500000;
            break;
#endif

#ifdef B2000000
        case 2000000:
            retval = B2000000;
            break;
#endif

#ifdef B2500000
        case 2500000:
            retval = B2500000;
            break;
#endif

#ifdef B3000000
        case 3000000:
            retval = B3000000;
            break;
#endif

#ifdef B3500000
        case 3500000:
            retval = B3500000;
            break;
#endif

#ifdef B4000000
        case 4000000:
            retval = B4000000;
            break;
#endif

        default:
            retval = 0;
            break;
    }

    return(retval);
}

int uart_test(void)
{
	struct termios options;
	unsigned long baudrate = DEFAULT_RATE;
	char tx_data=DEFAULT_START_TX_DATA;
	int size = DEFAULT_TX_SIZE;

	int *tx = NULL, *rx = NULL;
	int iores, iocount;
	int fd[9];
	int ret = 0;

	char device_node[100] = {0};
	int i;
	unsigned long long test_cnt = 0;
	
	for (i = 0; i < 9; i++) {

		//uart port 1~8 = /dev/ttyUSB0 ~ 7
		//uart port 9     = /dev/ttymxc1

		if (i < 8)
			sprintf(device_node, "/dev/ttyUSB%d", i);
		else
			sprintf(device_node, "/dev/ttymxc%d", 1);
		fd[i] = open(device_node, O_RDWR | O_NOCTTY);	//dev open
		if (fd[i] == -1) {	//dev open error
			printf("open_port: Unable to open serial port - %s", device_node);
			return -1;
		}

		// dev setting
		fcntl(fd[i], F_SETFL, 0);
		tcgetattr(fd[i], &options);
		options.c_cflag &= ~CSTOPB;
		options.c_cflag &= ~CSIZE;
		options.c_cflag &= ~PARENB;
		options.c_cflag &= ~PARODD;
		options.c_cflag |= CS8;
		options.c_cflag &= ~CRTSCTS;

		options.c_lflag &= ~(ICANON | IEXTEN | ISIG | ECHO);
		options.c_oflag &= ~OPOST;
		options.c_iflag &= ~(ICRNL | INPCK | ISTRIP | IXON | BRKINT );

		options.c_cc[VMIN] = 1;
		options.c_cc[VTIME] = 0;

		options.c_cflag |= (CLOCAL | CREAD);
		
		baudrate = DEFAULT_RATE;
		if(!baudrate_map(baudrate))
			baudrate = DEFAULT_RATE;
		if(baudrate) {
			cfsetispeed(&options, baudrate_map(baudrate));	//rx Baudrate setting
			cfsetospeed(&options, baudrate_map(baudrate));	//tx Baudrate setting
		}
		tcsetattr(fd[i], TCSANOW, &options);
		//printf("UART%d %lu, %dbit, %dstop, %s, HW flow %s\n", i, baudrate, 8,
		//       (options.c_cflag & CSTOPB) ? 2 : 1,
		//       (options.c_cflag & PARODD) ? "PARODD" : "PARENB",
		//       (options.c_cflag & CRTSCTS) ? "enabled" : "disabled");
	}

	// test process
	tx = malloc(size);

	for(i = 0;i < 9; i++) {
	//tx
		memset(tx, tx_data, size);
		write(fd[i], tx, size);
		//printf("fd[%d] Send 0x%02X data, %d bytes.\n", i, tx_data, size);
		tx_data = (tx_data + 1) & 0xff;
		
		usleep(500 * 1000);
	//rx
		iores = ioctl(fd[i], FIONREAD, &iocount);
		if(!iocount || size != iocount) {
			printf("fd[%d] recv packet error %lld !!!\n", i, test_cnt);
			if (rx)
				free(rx);
			return -1;
		}

		rx = malloc(iocount);
		iores = read(fd[i], rx, iocount);

		if (memcmp(tx, rx, iocount)) {
			printf("fd[%d] recv packet error %lld !!!\n", i, test_cnt);
			if (rx)
				free(rx);
			ret = -1;
			goto exit;
		}

		if (rx)
			free(rx);
		
		printf("uart port[%d] Recv %d bytes, memory compare ok\n\n", i, iocount);
		test_cnt++;
	}

exit :
	if (tx)
		free(tx);

	for (i = 0; i < 9; i++)
		close(fd[i]);
	printf("uart test exit\n");

	return ret;
}
