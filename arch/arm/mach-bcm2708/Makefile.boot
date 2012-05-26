DTC_FLAGS ?= -p 4096

dtb-$(CONFIG_MACH_BCM2708)	+= bcm2835-rpi-a.dtb bcm2835-rpi-b.dtb

   zreladdr-y	:= 0x00008000
params_phys-y	:= 0x00000100
initrd_phys-y	:= 0x00800000
