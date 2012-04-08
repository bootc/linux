EXTRA_CFLAGS += -I$(srctree)/drivers/target/

obj-$(CONFIG_SCSI_IBMVSCSI)	+= ibmvscsic.o

ibmvscsic-y			+= ibmvscsi.o
ibmvscsic-$(CONFIG_PPC_PSERIES)	+= rpa_vscsi.o 

obj-$(CONFIG_SCSI_IBMVSCSIS)	+= ibmvscsis.o
obj-$(CONFIG_SCSI_IBMVFC)	+= ibmvfc.o
