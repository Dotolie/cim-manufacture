/*
 * Copyright 2014 MVtech Co., Ltd, Inc. All Rights Reserved.
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <termio.h>
#include <sys/ioctl.h>
#include <mtd/mtd-user.h>

#include <sys/time.h>

#define TEMP_PATH	"/sys/devices/virtual/thermal/thermal_zone0/temp"

#define UNIT_CYLINDERS	1024
int fpga_ddwrite(const char *inputfile, const char *outfile, long size)
{
	int ret;
	FILE *fin = NULL, *fout = NULL;
	long write_size = size;
	unsigned char *pBuf = NULL;

	fin = fopen(inputfile, "rb");
	
	if (!fin) {
		printf("can't open input file:%s : %s",
					inputfile, strerror(errno));
		return -1;
	}

	fout = fopen(outfile, "wb");
	if (!fout) {
		printf("can't open output file:%s : %s",
					outfile, strerror(errno));
		goto error;
	}

	pBuf = (unsigned char *)malloc(UNIT_CYLINDERS);
	if(!pBuf)	{
		printf("Buff malloc error!\n");
		goto error;
	}

	printf("==============================================================================\n");
	printf("dd if=%s of=%s bs=1 size=%d\n", inputfile, outfile, (unsigned int)size);

	while (write_size > UNIT_CYLINDERS) {

		memset(pBuf, 0, UNIT_CYLINDERS);

		ret = fread(pBuf, 1, UNIT_CYLINDERS, fin);
		if (ret < UNIT_CYLINDERS) {
			printf("fread error:%s :%s ",
						inputfile, strerror(errno));
			goto error;
		}

		ret = fwrite(pBuf, 1, UNIT_CYLINDERS, fout);
		if (ret < UNIT_CYLINDERS) {
			printf("fwrite error:%s : %s", outfile, strerror(errno));
			goto error;
		}
		sync();
		
		write_size -= UNIT_CYLINDERS;
		printf("\rProgress : %d / %d", (unsigned int)(size-write_size), (unsigned int)size);
		sync();
	}
	
	if(write_size > 0 ) {
		memset(pBuf, 0, UNIT_CYLINDERS);
		
		ret = fread(pBuf, 1, write_size, fin);
		if (ret < write_size) {
			printf("fread error:%s :%s ",
						inputfile, strerror(errno));
			goto error;
		}

		ret = fwrite(pBuf, 1, write_size, fout);
		if (ret < write_size) {
			printf("fwrite error:%s : %s", outfile, strerror(errno));
			goto error;
		}
		sync();
		
		printf("\rProgress : %d / %d", (unsigned int)(size), (unsigned int)size);
	}

	printf("\nfpga_ddwrite complete\n");

	printf("\n");
	free(pBuf);
	if (fout)
		fclose(fout);
	fclose(fin);
	sync();

	return 0;

error:	
	if(pBuf)
		free(pBuf);
	if (fout)
		fclose(fout);
	if (fin)
		fclose(fin);

	return -1;

}

int fpga_UpgradeFirmware(char *pFile)
{
	int i;
	int ret;
	FILE *fp = NULL;
	unsigned int image_size = 0;
	mtd_info_t mtd_info;           // the MTD structure
	erase_info_t ei;               // the erase block structure

	fp = fopen(pFile, "rb");
	if (!fp) {
		printf("%s file open fail\n", pFile);
		return -1;
	}
	fseek(fp, 0, SEEK_END);
	image_size = ftell(fp);
	fclose(fp);

	int fd = open("/dev/mtd0", O_RDWR); // open the mtd device for reading and 
	if (fd < 0) {
		printf("/dev/mtd0 open fail %d\n", fd);
		return -1;
	}

	ioctl(fd, MEMGETINFO, &mtd_info);

	printf("MTD Type: %x\nMTD total size: %x bytes\nMTD erase size: %x bytes\n",
				mtd_info.type, mtd_info.size, mtd_info.erasesize);

	ei.length = mtd_info.erasesize;
	for(ei.start = 0; ei.start < mtd_info.size; ei.start += ei.length) {
		ioctl(fd, MEMUNLOCK, &ei);
		printf("\rEraseing Block %#x", ei.start);
		ioctl(fd, MEMERASE, &ei);
	}    

	close(fd);

	usleep(100000);
#if 1
	ret = fpga_ddwrite(pFile, "/dev/mtd0", image_size);
	if (ret < 0) {
		printf("fpga write fail\n");
		return -1;
	}
#else
	ret = system("dd if=dump_1st.bin of=/dev/mtd0 bs=1024 count=4096");
	if (ret < 0) {
		printf("dd write fail\n");
		return -1;
	}
#endif
	return 0;
}

int print_temp(void)
{
	int fd;
	char buf[PATH_MAX];
	char *dev;
	int n;

	dev = TEMP_PATH;
	if((fd= open(dev, O_RDONLY)) < 0) {
		printf("Error %s not exist\n", dev);
		return -1;
	}

	n = read(fd, buf, sizeof(buf));
	buf[n-1] = '\0';
	printf("temp : %s\n", buf);
	close(fd);

	return 0;
}

int fpga_upgrade(char *pFile)
{
	int ret;	
	struct timeval begin, end;
	int sec, usec, run_time;
	
	if (!pFile)
		return -1;
	

	usleep(100000);
	
	gettimeofday(&begin, NULL);
	
	ret = fpga_UpgradeFirmware(pFile);
	if (ret < 0)
		return -1;
	
	gettimeofday(&end, NULL);
	sec = end.tv_sec - begin.tv_sec;
	usec = end.tv_usec - begin.tv_usec;
	if (usec < 0) {
		sec--;
		usec = usec + 1000000;
	}
	run_time = (sec * 1000000) + usec;

	printf("fpga update time : %d min %d sec (%d sec)\n", sec / 60, sec % 60, sec);

	usleep(2000000);
	

	return 0;
}


