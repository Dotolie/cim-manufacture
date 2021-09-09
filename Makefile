# MACHIN_NAME : Toolcahin ??Machine Name ?¤ì •.
#MACHINE_NAME=/home/kimjs/mntdisk/project/samsung/iot/fenix/build/toolchains/gcc-linaro-aarch64-linux-gnu/bin/aarch64-linux-gnu-
#MACHINE_NAME=aarch64-linux-gnu-
#CC				=${MACHINE_NAME}gcc
#CXX				=${MACHINE_NAME}g++
#AR				=${MACHINE_NAME}ar
#LD				=${MACHINE_NAME}ld
#NM				=${MACHINE_NAME}nm
#STRIP			=${MACHINE_NAME}strip
#OBJCOPY			=${MACHINE_NAME}objcopy

LDFLAGS 		+= -lpthread
LDFLAGS 		+= -Wl,-rpath=./lib/
CFLAGS  		+= #-std=c99

INC_DIRS 		= -I./include
LIB_DIRS		= -L./lib

OUTPUT_DIR = ./

APP=$(OUTPUT_DIR)manufacture

all: $(APP)

$(OUTPUT_DIR)manufacture: manufacture.c mac.c uart.c utils.c memtester.c tests.c fpga_updater2.c
	$(CC) $(CFLAGS) $(INC_DIRS) -o $@ $^ $(LIB_DIRS) $(LDFLAGS)
$(OUTPUT_DIR)%.o: %.c	
	$(CC) $(CFLAGS) $(INC_DIRS) -c $< -o $@

clean:	
	rm -rf manufacture *.o 
