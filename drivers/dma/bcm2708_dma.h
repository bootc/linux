/*
 * Copyright 2010 Broadcom
 * Copyright 2012 Simon Arlott
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _DRIVERS_DMA_BCM2708_DMA_H
#define _DRIVERS_DMA_BCM2708_DMA_H

#define PERIPHERAL_BASE		0x20000000
#define PERIPHERAL_MASK		0xff000000
#define PERIPHERAL_OFFSET	0x5e000000

#define CACHE_LINE_SIZE		32
#define CACHE_LINE_MASK		(CACHE_LINE_SIZE - 1)
#define MAX_CHANS		16
#define MAX_WAITS		((1 << 5) - 1)
/*
 * Slightly smaller than supported to include alignment for transfers that have
 * to span multiple CBs (CACHE_LINE_SIZE could be replaced with 1).
 */
#define MAX_LEN(n)		((n)->lite ? (size_t)((1 << 16) - CACHE_LINE_SIZE) : (size_t)((1 << 30) - CACHE_LINE_SIZE))

/* 2D mode */
#define MAX_XLENGTH		((1 << 16) - 1)
#define MAX_YLENGTH		((1 << 14) - 1)
#define MIN_STRIDE		(-(1 << 15))
#define MAX_STRIDE		((1 << 15) - 1)

#define REG_CS			0x00	/* Control and Status */
#define BCM_CS_ACTIVE		BIT(0)	/* Activate (rw) */
#define BCM_CS_END		BIT(1)	/* Completion Flag (w1c) */
#define BCM_CS_INT		BIT(2)	/* Interrupt Status (w1c) */
#define BCM_CS_DREQ		BIT(3)	/* DREQ State (ro) */
#define BCM_CS_PAUSED		BIT(4)	/* Paused State (ro) */
#define BCM_CS_DREQ_PAUSED	BIT(5)	/* Paused by DREQ (ro) */
#define BCM_CS_WR_WAITING	BIT(6)	/* Waiting for outstanding writes (ro) */
#define BCM_CS_ERROR		BIT(7)	/* Error Status (ro) */
#define BCM_CS_PRI_GET(n)	((n >> 16) & 0xF)	/* AXI Priority Level (rw) */
#define BCM_CS_PRI_SET(n)	((n & 0xF) << 16)	/* AXI Priority Level (rw) */
#define BCM_CS_PANIC_PRI_GET(n)	((n >> 20) & 0xF)	/* AXI Panic Priority Level (rw) */
#define BCM_CS_PANIC_PRI_SET(n)	((n & 0xF) << 20)	/* AXI Panic Priority Level (rw) */
#define BCM_CS_WR_WAIT		BIT(28)	/* Wait for outstanding writes (rw) */
#define BCM_CS_DISDEBUG		BIT(29)	/* Disable debug pause signal (rw) */
#define BCM_CS_ABORT		BIT(30)	/* Abort current CB (w1sc) */
#define BCM_CS_RESET		BIT(31)	/* Channel reset (w1sc) */

#define REG_CONBLK_AD		0x04	/* Control Block Address (rw) */

#define REG_CB_TI		0x08	/* Control Block Transfer Information (ro) */
#define BCM_TI_INTEN		BIT(0)	/* Interrupt Enable */
#define BCM_TI_TDMODE		BIT(1)	/* 2D Mode */
#define BCM_TI_WAIT_RESP	BIT(3)	/* Wait Response */
#define BCM_TI_DST_INC		BIT(4)	/* Destination Address Increment */
#define BCM_TI_DST_WIDTH	BIT(5)	/* Destination Width (0=32, 1=128) */
#define BCM_TI_DST_DREQ		BIT(6)	/* Control Destination Writes with DREQ */
#define BCM_TI_DST_IGNORE	BIT(7)	/* Ignore (do not perform) Writes */
#define BCM_TI_SRC_INC		BIT(8)	/* Destination Address Increment */
#define BCM_TI_SRC_WIDTH	BIT(9)	/* Destination Width (0=32, 1=128) */
#define BCM_TI_SRC_DREQ		BIT(10)	/* Control Source Reads with DREQ */
#define BCM_TI_SRC_IGNORE	BIT(11)	/* Ignore (do not perform) Reads */
#define BCM_TI_BURST_LEN_GET(n)	((n >> 12) & 0xF)	/* Burst Transfer Length (words) */
#define BCM_TI_BURST_LEN_SET(n)	((n & 0xF) << 12)	/* Burst Transfer Length (words) */
#define BCM_TI_BURST_CHAN(n)	((n)->lite ? 4 : 8)
#define BCM_TI_WIDTH_MULT	4
#define BCM_TI_PERMAP_GET(n)	((n >> 16) & 0x1F)	/* Periphal Mapping */
#define BCM_TI_PERMAP_SET(n)	((n & 0x1F) << 16)	/* Periphal Mapping */
#define BCM_TI_WAITS_GET(n)	((n >> 21) & MAX_WAITS)	/* Add Wait Cycles */
#define BCM_TI_WAITS_SET(n)	((n & MAX_WAITS) << 21)	/* Add Wait Cycles */
#define BCM_TI_NO_WIDE_BURSTS	BIT(26)	/* No wide writes as 2 beat AXI bursts */

#define REG_CB_SOURCE_AD	0x0c	/* Control Block Source Address (ro) */
#define REG_CB_DEST_AD		0x10	/* Control Block Destination Address (ro) */
#define REG_CB_TXFR_LEN		0x14	/* Control Block Transfer Length (ro) */
#define REG_CB_STRIDE		0x18	/* Control Block 2D Stride (ro) */
#define REG_CB_NEXTCONBK	0x1c	/* Control Block Next CB Address (ro) */

#define REG_DEBUG		0x20
#define BCM_DEBUG_RLSN_ERR(n)	(n & BIT(0))		/* Read Last Not Set Error (w1c) */
#define BCM_DEBUG_FIFO_ERR(n)	(n & BIT(1))		/* FIFO Error (w1c) */
#define BCM_DEBUG_READ_ERR(n)	(n & BIT(2))		/* Read Error (w1c) */
#define BCM_DEBUG_OUT_WR(n)	((n >> 4) & 0xF)	/* Outstanding Writes Count (ro) */
#define BCM_DEBUG_DMA_ID(n)	((n >> 8) & 0xFF)	/* DMA AXI ID (ro) */
#define BCM_DEBUG_DMA_STATE(n)	((n >> 16) & 0x1FF)	/* State Machine State (ro) */
#define BCM_DEBUG_VERSION(n)	((n >> 25) & 0x7)
#define BCM_DEBUG_LITE(n)	(n & BIT(28))

#define REG_INT_STATUS		0xfe0	/* Interrupt status of each DMA channel */
#define REG_ENABLE		0xff0	/* Global enable bits for each DMA channel */

enum dmadev_idx {
	D_FULL,
	D_LITE,
	D_MAX
};

struct bcm2708_dmachan {
	struct device *dev;
	struct dma_pool *pool;

	void __iomem *base;
	int irq;

	int id;
	int axi_id;
	bool lite;
	int version;

	struct dma_chan dmachan;
	struct spinlock prep_lock;
	struct list_head prep_list;
	struct spinlock lock;
	struct list_head pending;
	struct list_head running;
	struct list_head completed;
	bool active;
	bool paused;
	u32 cfg;
	struct dma_slave_config	slcfg;

	struct tasklet_struct tasklet;
};

struct bcm2708_dmadev {
	struct device *dev;
	struct dma_pool *pool;

	/* Channels 0-14, 15 */
	struct resource res[2];
	void __iomem *base[2];

	/* Full/lite devices */
	struct dma_device dmadev[2];
};

struct bcm2708_dmacb {
	u32 ti;
	u32 src;
	u32 dst;
	u32 len;
	u32 stride;
	u32 next;
	u64 pad;
} __packed;

struct bcm2708_dmadesc {
	struct bcm2708_dmacb *cb;
	dma_addr_t phys;
};

struct bcm2708_dmatx {
	struct bcm2708_dmachan *chan;
	unsigned int count;

	struct dma_async_tx_descriptor dmatx;
	struct list_head list;

	int *memset_value;
	dma_addr_t memset_phys;

	struct bcm2708_dmadesc desc[0];
};

#endif
