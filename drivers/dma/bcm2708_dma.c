/*
 * Copyright 2010 Broadcom
 * Copyright 2012 Simon Arlott
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * CB creation loops copied from fsldma.c (Freescale Semiconductor, Inc.)
 *
 * BCM2708DMA_CONFIG takes a struct bcm2708_dmacfg and sets the additional
 * config parameters (DREQ, etc.)
 *
 * Note: the VideoCore uses DMA channels too, so we can't safely enable or
 * disable channels for power saving without a race condition
 */

#include <linux/bcm2708_dma.h>
#include <linux/bitops.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/dmaengine.h>
#include <linux/dmapool.h>
#include <linux/dma-direction.h>
#include <linux/dma-mapping.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/platform_device.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <asm/sizes.h>

#include "dmaengine.h"
#include "bcm2708_dma.h"

#define MODULE_NAME "bcm2708_dma"

static inline struct bcm2708_dmachan *to_bcmchan(struct dma_chan *dmachan)
{
	return container_of(dmachan, struct bcm2708_dmachan, dmachan);
}

static inline struct bcm2708_dmatx *to_bcmtx(
	struct dma_async_tx_descriptor *dmatx)
{
	return container_of(dmatx, struct bcm2708_dmatx, dmatx);
}

static inline u32 bcm2708_dma_make_cfg(struct bcm2708_dmacfg *cfg)
{
	return (cfg->src_dreq ? BCM_TI_SRC_DREQ : 0)
		| (cfg->dst_dreq ? BCM_TI_DST_DREQ : 0)
		| BCM_TI_PERMAP_SET(cfg->per)
		| BCM_TI_WAITS_SET(cfg->waits);
}

static int bcm2708_dma_alloc_chan(struct dma_chan *dmachan)
{
	struct bcm2708_dmachan *bcmchan = to_bcmchan(dmachan);
	unsigned long flags;

	dev_vdbg(bcmchan->dev, "%s: %d\n", __func__, bcmchan->id);

	spin_lock_irqsave(&bcmchan->lock, flags);
	bcmchan->cfg = 0;
	spin_unlock_irqrestore(&bcmchan->lock, flags);
	return 0;
}

static void bcm2708_dma_free_tx(struct bcm2708_dmatx *bcmtx)
{
	int i;

	for (i = 0; i < bcmtx->count; i++)
		dma_pool_free(bcmtx->chan->pool, bcmtx->desc[i].cb,
				bcmtx->desc[i].phys);
	if (bcmtx->memset_value)
		dma_pool_free(bcmtx->chan->pool, bcmtx->memset_value,
				bcmtx->memset_phys);
	kfree(bcmtx);
}

static void bcm2708_dma_delete(struct list_head *list)
{
	struct bcm2708_dmatx *bcmtx;
	struct bcm2708_dmatx *tmp;

	list_for_each_entry_safe(bcmtx, tmp, list, list) {
		list_del(&bcmtx->list);
		bcm2708_dma_free_tx(bcmtx);
	}
}

static void bcm2708_dma_abort(struct bcm2708_dmachan *bcmchan)
{
	int timeout;
	u32 status;
	u32 block;

	dev_vdbg(bcmchan->dev, "%s: %d pausing\n", __func__, bcmchan->id);

	/* Pause */
	writel(0, bcmchan->base + REG_CS);

	/* Wait for pause */
	status = 0;
	timeout = 1000;
	while (!(status & BCM_CS_PAUSED) && timeout-- > 0) {
		status = readl(bcmchan->base + REG_CS);
		udelay(1);
	}

	block = readl(bcmchan->base + REG_CONBLK_AD);
	dev_vdbg(bcmchan->dev, "%s: %d paused %08x block %08x\n",
		__func__, bcmchan->id, status, block);

	/* Abort */
	writel(0, bcmchan->base + REG_CONBLK_AD);
	writel(BCM_CS_ABORT | BCM_CS_ACTIVE, bcmchan->base + REG_CS);

	block = readl(bcmchan->base + REG_CONBLK_AD);
	dev_vdbg(bcmchan->dev, "%s: %d aborted %08x block %08x\n",
		__func__, bcmchan->id, status, block);

	/* Wait for finish */
	status = 0;
	timeout = 1000;
	while ((status & (BCM_CS_WR_WAIT | BCM_CS_PAUSED | BCM_CS_ACTIVE))
			&& timeout-- > 0) {
		status = readl(bcmchan->base + REG_CS);
		udelay(1);
	}

	block = readl(bcmchan->base + REG_CONBLK_AD);
	dev_vdbg(bcmchan->dev, "%s: %d finished %08x block %08x\n",
		__func__, bcmchan->id, status, block);

	/* Reset */
	writel(BCM_CS_RESET, bcmchan->base + REG_CS);

	block = readl(bcmchan->base + REG_CONBLK_AD);
	dev_vdbg(bcmchan->dev, "%s: %d reset %08x block %08x\n",
		__func__, bcmchan->id, status, block);

	bcmchan->active = false;
	bcmchan->paused = false;
}

static void bcm2708_dma_free_chan(struct dma_chan *dmachan)
{
	struct bcm2708_dmachan *bcmchan = to_bcmchan(dmachan);
	unsigned long flags;

	dev_vdbg(bcmchan->dev, "%s: %d\n", __func__, bcmchan->id);

	spin_lock_irqsave(&bcmchan->prep_lock, flags);
	bcm2708_dma_delete(&bcmchan->prep_list);
	spin_unlock_irqrestore(&bcmchan->prep_lock, flags);

	spin_lock_irqsave(&bcmchan->lock, flags);
	bcm2708_dma_delete(&bcmchan->pending);

	if (unlikely(bcmchan->active || bcmchan->paused)) {
		WARN_ON(1);
		bcm2708_dma_abort(bcmchan);
	}

	bcm2708_dma_delete(&bcmchan->running);
	bcm2708_dma_delete(&bcmchan->completed);
	spin_unlock_irqrestore(&bcmchan->lock, flags);
}

static inline void bcm2708_dma_chain_cb(struct bcm2708_dmatx *prev,
	struct bcm2708_dmatx *next)
{
	BUG_ON(prev->desc[prev->count - 1].cb->next);
	prev->desc[prev->count - 1].cb->next = next->dmatx.phys;
}


static inline void bcm2708_dma_debug_cb(struct bcm2708_dmatx *bcmtx)
{
	struct bcm2708_dmachan *bcmchan = bcmtx->chan;
	int i;

	for (i = 0; i < bcmtx->count; i++) {
		dev_vdbg(bcmchan->dev, "%d: CB %d:\n", bcmchan->id, i);
		dev_vdbg(bcmchan->dev, "%d:  TI = %08x\n", bcmchan->id,
			bcmtx->desc[i].cb->ti);
		dev_vdbg(bcmchan->dev, "%d:  SRC = %08x\n", bcmchan->id,
			bcmtx->desc[i].cb->src);
		dev_vdbg(bcmchan->dev, "%d:  DST = %08x\n", bcmchan->id,
			bcmtx->desc[i].cb->dst);
		if (bcmtx->desc[i].cb->ti & BCM_TI_TDMODE) {
			dev_vdbg(bcmchan->dev, "%d:  XLEN = %04x\n",
				bcmchan->id,
				bcmtx->desc[i].cb->len & 0xFFFF);
			dev_vdbg(bcmchan->dev, "%d:  YLEN = %04x\n",
				bcmchan->id,
				(bcmtx->desc[i].cb->len >> 16) & 0xFFFF);
			dev_vdbg(bcmchan->dev, "%d:  S_STRIDE = %04x\n",
				bcmchan->id,
				bcmtx->desc[i].cb->stride & 0xFFFF);
			dev_vdbg(bcmchan->dev, "%d:  D_STRIDE = %04x\n",
				bcmchan->id,
				(bcmtx->desc[i].cb->stride >> 16) & 0xFFFF);
		} else {
			dev_vdbg(bcmchan->dev, "%d:  LEN = %08x\n", bcmchan->id,
				bcmtx->desc[i].cb->len);
		}
		dev_vdbg(bcmchan->dev, "%d:  NEXT = %08x\n", bcmchan->id,
			bcmtx->desc[i].cb->next);
	}
}

static dma_cookie_t bcm2708_dma_submit(struct dma_async_tx_descriptor *dmatx)
{
	struct bcm2708_dmatx *bcmtx = to_bcmtx(dmatx);
	struct bcm2708_dmachan *bcmchan = bcmtx->chan;
	unsigned long flags;
	dma_cookie_t cookie;

	spin_lock_irqsave(&bcmchan->prep_lock, flags);
	list_del(&bcmtx->list);
	spin_unlock_irqrestore(&bcmchan->prep_lock, flags);
	
	spin_lock_irqsave(&bcmchan->lock, flags);
	if (!list_empty(&bcmchan->pending))
		bcm2708_dma_chain_cb(list_last_entry(&bcmchan->pending,
				struct bcm2708_dmatx, list), bcmtx);
	list_add_tail(&bcmtx->list, &bcmchan->pending);
	cookie = dma_cookie_assign(&bcmtx->dmatx);

	dev_vdbg(bcmchan->dev, "%s: %d: %08x\n", __func__, bcmchan->id,
		cookie);
	bcm2708_dma_debug_cb(bcmtx);
	spin_unlock_irqrestore(&bcmchan->lock, flags);

	return cookie;
}

static struct bcm2708_dmatx *bcm2708_dma_alloc_cb(struct bcm2708_dmatx *bcmtx,
	int count)
{
	int i;

	for (i = bcmtx->count; i < count; i++) {
		bcmtx->desc[i].cb = dma_pool_alloc(bcmtx->chan->pool,
				GFP_NOWAIT, &bcmtx->desc[i].phys);
		if (unlikely(!bcmtx->desc[i].cb)) {
			bcm2708_dma_free_tx(bcmtx);
			return NULL;
		}
		if (i > 0)
			bcmtx->desc[i - 1].cb->next = bcmtx->desc[i].phys;
		bcmtx->desc[i].cb->pad = 0;
		bcmtx->count++;
	}
	bcmtx->desc[bcmtx->count - 1].cb->next = 0;
	return bcmtx;
}

static struct bcm2708_dmatx *bcm2708_dma_alloc_tx(
	struct bcm2708_dmachan *bcmchan, unsigned long flags, int count)
{
	struct bcm2708_dmatx *bcmtx;

	if (unlikely(count <= 0))
		return NULL;

	bcmtx = kzalloc(sizeof(*bcmtx) + count * sizeof(bcmtx->desc[0]),
			GFP_NOWAIT);
	if (unlikely(!bcmtx))
		return NULL;

	bcmtx->chan = bcmchan;
	bcmtx->count = 0;
	bcmtx = bcm2708_dma_alloc_cb(bcmtx, count);
	if (unlikely(!bcmtx))
		return NULL;

	/**
	 * Ignored flags:
	 *   DMA_PREP_INTERRUPT	(this is always done)
	 *   DMA_CTRL_ACK	(descriptors aren't reused)
	 *   DMA_PREP_CONTINUE	(operations are executed in order)
	 *   DMA_PREP_FENCE	(operations are executed in order)
	 *
	 * Handled flags:
	 *   DMA_COMPL_SKIP_SRC_UNMAP
	 *   DMA_COMPL_SKIP_DEST_UNMAP
	 *   DMA_COMPL_SRC_UNMAP_SINGLE
	 *   DMA_COMPL_DEST_UNMAP_SINGLE
	 */

	bcmtx->dmatx.cookie = -EBUSY;
	bcmtx->dmatx.flags = flags;
	bcmtx->dmatx.chan = &bcmchan->dmachan;
	bcmtx->dmatx.phys = bcmtx->desc[0].phys;
	bcmtx->dmatx.tx_submit = bcm2708_dma_submit;
	return bcmtx;
}

static struct bcm2708_dmatx *bcm2708_dma_realloc_tx(struct bcm2708_dmatx *bcmtx,
	int count)
{
	struct bcm2708_dmatx *tmp;

	BUG_ON(unlikely(count <= 0));
	if (unlikely(count <= bcmtx->count)) {
		while (bcmtx->count > count) {
			bcmtx->count--;
			dma_pool_free(bcmtx->chan->pool,
					bcmtx->desc[bcmtx->count].cb,
					bcmtx->desc[bcmtx->count].phys);
		}
	}

	tmp = krealloc(bcmtx, sizeof(*bcmtx) + count * sizeof(bcmtx->desc[0]),
			GFP_NOWAIT);
	if (unlikely(!tmp)) {
		bcm2708_dma_free_tx(bcmtx);
		return NULL;
	}
	return bcm2708_dma_alloc_cb(tmp, count);
}

static struct dma_async_tx_descriptor *bcm2708_dma_prep_memcpy(
	struct dma_chan *dmachan, dma_addr_t dst, dma_addr_t src,
	size_t len, unsigned long flags)
{
	struct bcm2708_dmachan *bcmchan = to_bcmchan(dmachan);
	struct bcm2708_dmatx *bcmtx;
	size_t copy;
	int i = -1;

	dev_vdbg(bcmchan->dev, "%s: %d: %08x(+%d)=>%08x [%lu]\n", __func__,
		bcmchan->id, src, len, dst, flags);

	if (unlikely(len < 0))
		return NULL;

	bcmtx = bcm2708_dma_alloc_tx(bcmchan, flags, 1);
	if (unlikely(!bcmtx))
		return NULL;

	do {
		copy = min(len, MAX_LEN(bcmchan));

		bcmtx = bcm2708_dma_realloc_tx(bcmtx, ++i + 1);
		if (unlikely(!bcmtx))
			return NULL;

		bcmtx->desc[i].cb->ti = BCM_TI_DST_INC | BCM_TI_SRC_INC
			| BCM_TI_BURST_LEN_SET(BCM_TI_BURST_CHAN(bcmchan))
			| bcmchan->cfg;
		bcmtx->desc[i].cb->src = src;
		bcmtx->desc[i].cb->dst = dst;
		bcmtx->desc[i].cb->len = copy;
		bcmtx->desc[i].cb->stride = 0;

		len -= copy;
		src += copy;
		dst += copy;
	} while (len);

	bcmtx->desc[i].cb->ti |= BCM_TI_INTEN | BCM_TI_WAIT_RESP;

	spin_lock_irqsave(&bcmchan->prep_lock, flags);
	list_add_tail(&bcmtx->list, &bcmchan->prep_list);
	spin_unlock_irqrestore(&bcmchan->prep_lock, flags);
	return &bcmtx->dmatx;
}

static struct dma_async_tx_descriptor *bcm2708_dma_prep_memset(
	struct dma_chan *dmachan, dma_addr_t dst, int value, size_t len,
	unsigned long flags)
{
	struct bcm2708_dmachan *bcmchan = to_bcmchan(dmachan);
	struct bcm2708_dmatx *bcmtx;
	size_t copy;
	int i = -1;

	dev_vdbg(bcmchan->dev, "%s: %d: %08x=>%08x(+%d) [%lu]\n", __func__,
		bcmchan->id, value, len, dst, flags);

	if (unlikely(len < 0))
		return NULL;

	bcmtx = bcm2708_dma_alloc_tx(bcmchan, flags, 1);
	if (unlikely(!bcmtx))
		return NULL;

	/* this wastes 4 bytes but avoids using a second pool */
	bcmtx->memset_value = dma_pool_alloc(bcmtx->chan->pool,
				GFP_NOWAIT, &bcmtx->memset_phys);
	if (unlikely(!bcmtx->memset_value)) {
		bcm2708_dma_free_tx(bcmtx);
		return NULL;
	}

	do {
		copy = min(len, MAX_LEN(bcmchan));

		bcmtx = bcm2708_dma_realloc_tx(bcmtx, ++i + 1);
		if (unlikely(!bcmtx))
			return NULL;

		bcmtx->desc[i].cb->ti = BCM_TI_DST_INC
			| BCM_TI_BURST_LEN_SET(BCM_TI_BURST_CHAN(bcmchan))
			| bcmchan->cfg;
		bcmtx->desc[i].cb->src = bcmtx->memset_phys;
		bcmtx->desc[i].cb->dst = dst;
		bcmtx->desc[i].cb->len = copy;
		bcmtx->desc[i].cb->stride = 0;

		len -= copy;
		dst += copy;
	} while (len);

	bcmtx->desc[i].cb->ti |= BCM_TI_INTEN | BCM_TI_WAIT_RESP;
	*bcmtx->memset_value = value;

	spin_lock_irqsave(&bcmchan->prep_lock, flags);
	list_add_tail(&bcmtx->list, &bcmchan->prep_list);
	spin_unlock_irqrestore(&bcmchan->prep_lock, flags);
	return &bcmtx->dmatx;
}

static struct dma_async_tx_descriptor *bcm2708_dma_prep_interrupt(
	struct dma_chan *dmachan, unsigned long flags)
{
	struct bcm2708_dmachan *bcmchan = to_bcmchan(dmachan);
	struct bcm2708_dmatx *bcmtx;

	dev_vdbg(bcmchan->dev, "%s: %d: %lu\n", __func__,
		bcmchan->id, flags);

	bcmtx = bcm2708_dma_alloc_tx(bcmchan, flags, 1);
	if (unlikely(!bcmtx))
		return NULL;

	bcmtx->desc[0].cb->ti = BCM_TI_INTEN | BCM_TI_SRC_IGNORE
		| BCM_TI_DST_IGNORE;
	bcmtx->desc[0].cb->src = 0;
	bcmtx->desc[0].cb->dst = 0;
	bcmtx->desc[0].cb->len = 0;
	bcmtx->desc[0].cb->stride = 0;

	spin_lock_irqsave(&bcmchan->prep_lock, flags);
	list_add_tail(&bcmtx->list, &bcmchan->prep_list);
	spin_unlock_irqrestore(&bcmchan->prep_lock, flags);
	return &bcmtx->dmatx;
}

static struct dma_async_tx_descriptor *bcm2708_dma_prep_dma_sg(
	struct dma_chan *dmachan,
	struct scatterlist *dst_sg, unsigned int dst_nents,
	struct scatterlist *src_sg, unsigned int src_nents,
	unsigned long flags)
{
	struct bcm2708_dmachan *bcmchan = to_bcmchan(dmachan);
	struct bcm2708_dmatx *bcmtx;
	int max_count = max(src_nents, dst_nents);
	size_t src_avail, dst_avail;
	dma_addr_t src, dst;
	size_t len;
	int i = -1;

	dev_vdbg(bcmchan->dev, "%s: %d: %d=>%d [%lu]\n", __func__,
		bcmchan->id, src_nents, dst_nents, flags);

	if (unlikely(src_sg == NULL || dst_sg == NULL || max_count <= 0
			|| src_nents <= 0 || dst_nents <= 0))
		return NULL;

	bcmtx = bcm2708_dma_alloc_tx(bcmchan, flags, max_count);
	if (unlikely(!bcmtx))
		return NULL;

	src_avail = sg_dma_len(src_sg);
	dst_avail = sg_dma_len(dst_sg);

	while (true) {
		/* create the largest transaction possible */
		len = min_t(size_t, src_avail, dst_avail);
		len = min_t(size_t, len, MAX_LEN(bcmchan));
		if (len == 0)
			goto fetch;

		src = sg_dma_address(src_sg) + sg_dma_len(src_sg) - src_avail;
		dst = sg_dma_address(dst_sg) + sg_dma_len(dst_sg) - dst_avail;

		/* allocate and populate the descriptor */
		bcmtx = bcm2708_dma_realloc_tx(bcmtx, ++i + 1);
		if (unlikely(!bcmtx))
			return NULL;

		bcmtx->desc[i].cb->ti = BCM_TI_DST_INC | BCM_TI_SRC_INC
			| BCM_TI_BURST_LEN_SET(BCM_TI_BURST_CHAN(bcmchan))
			| bcmchan->cfg;
		bcmtx->desc[i].cb->src = src;
		bcmtx->desc[i].cb->dst = dst;
		bcmtx->desc[i].cb->len = len;
		bcmtx->desc[i].cb->stride = 0;

		/* update metadata */
		src_avail -= len;
		dst_avail -= len;

fetch:
		/* fetch the next dst scatterlist entry */
		if (dst_avail == 0) {
			/* no more entries: we're done */
			if (dst_nents == 0)
				break;

			/* fetch the next entry: if there are no more: done */
			dst_sg = sg_next(dst_sg);
			if (dst_sg == NULL)
				break;

			dst_nents--;
			dst_avail = sg_dma_len(dst_sg);
		}

		/* fetch the next src scatterlist entry */
		if (src_avail == 0) {
			/* no more entries: we're done */
			if (src_nents == 0)
				break;

			/* fetch the next entry: if there are no more: done */
			src_sg = sg_next(src_sg);
			if (src_sg == NULL)
				break;

			src_nents--;
			src_avail = sg_dma_len(src_sg);
		}
	}

	bcmtx->desc[i].cb->ti |= BCM_TI_INTEN | BCM_TI_WAIT_RESP;

	spin_lock_irqsave(&bcmchan->prep_lock, flags);
	list_add_tail(&bcmtx->list, &bcmchan->prep_list);
	spin_unlock_irqrestore(&bcmchan->prep_lock, flags);
	return &bcmtx->dmatx;
}

static struct dma_async_tx_descriptor *bcm2708_dma_prep_slave_sg(
	struct dma_chan *dmachan, struct scatterlist *sgl,
	unsigned int sg_len, enum dma_transfer_direction direction,
	unsigned long flags, void *context)
{
	struct bcm2708_dmachan *bcmchan = to_bcmchan(dmachan);
	struct bcm2708_dmatx *bcmtx;
	bool from = (direction == DMA_DEV_TO_MEM);
	size_t burst;
	size_t avail;
	dma_addr_t addr;
	size_t len;
	int i = -1;

	dev_vdbg(bcmchan->dev, "%s: %d: %p+%d [%d,%lu] %p\n", __func__,
		bcmchan->id, sgl, sg_len, direction, flags, context);

	if (unlikely(sgl == NULL || sg_len <= 0))
		return NULL;

	if (direction != DMA_MEM_TO_DEV && direction != DMA_DEV_TO_MEM) {
		dev_warn(bcmchan->dev, "%s: unsupported dir %d\n",
			__func__, direction);
		return NULL;
	}

	bcmtx = bcm2708_dma_alloc_tx(bcmchan, flags, sg_len);
	if (unlikely(!bcmtx))
		return NULL;

	avail = sg_dma_len(sgl);
	burst = min_t(size_t, (bcmchan->slcfg.src_addr_width
			* bcmchan->slcfg.src_maxburst)
				/ (from ? 4 : BCM_TI_WIDTH_MULT * 4),
			BCM_TI_BURST_CHAN(bcmchan)
				/ (from ? 1 : BCM_TI_WIDTH_MULT));
	if (burst == 0)
		burst = 1;

	while (true) {
		/* create the largest transaction possible */
		len = min_t(size_t, avail, MAX_LEN(bcmchan));
		if (len == 0)
			goto fetch;

		addr = sg_dma_address(sgl) + sg_dma_len(sgl) - avail;

		/* allocate and populate the descriptor */
		bcmtx = bcm2708_dma_realloc_tx(bcmtx, ++i + 1);
		if (unlikely(!bcmtx))
			return NULL;

		bcmtx->desc[i].cb->ti = (from ? BCM_TI_DST_INC : BCM_TI_SRC_INC)
			| (from ? BCM_TI_DST_WIDTH : BCM_TI_SRC_WIDTH)
			| (from ? 0 : BCM_TI_WAIT_RESP)
			| BCM_TI_BURST_LEN_SET(burst)
			| (bcmchan->cfg & ~(BCM_TI_SRC_DREQ | BCM_TI_DST_DREQ));
		if (bcmchan->slcfg.device_fc)
			bcmtx->desc[i].cb->ti |= from ? BCM_TI_SRC_DREQ
							: BCM_TI_DST_DREQ;
		bcmtx->desc[i].cb->src = from ? bcmchan->slcfg.src_addr : addr;
		bcmtx->desc[i].cb->dst = from ? addr : bcmchan->slcfg.src_addr;
		bcmtx->desc[i].cb->len = len;
		bcmtx->desc[i].cb->stride = 0;

		/* update metadata */
		avail -= len;

fetch:
		/* fetch the next dst scatterlist entry */
		if (avail == 0) {
			/* no more entries: we're done */
			if (sg_len == 0)
				break;

			/* fetch the next entry: if there are no more: done */
			sgl = sg_next(sgl);
			if (sgl == NULL)
				break;

			sg_len--;
			avail = sg_dma_len(sgl);
		}
	}
	bcmtx->desc[i].cb->ti |= BCM_TI_INTEN | BCM_TI_WAIT_RESP;

	spin_lock_irqsave(&bcmchan->prep_lock, flags);
	list_add_tail(&bcmtx->list, &bcmchan->prep_list);
	spin_unlock_irqrestore(&bcmchan->prep_lock, flags);
	return &bcmtx->dmatx;
}

static struct dma_async_tx_descriptor *bcm2708_dma_prep_cyclic(
	struct dma_chan *dmachan, dma_addr_t buf_addr, size_t buf_len,
	size_t period_len, enum dma_transfer_direction direction,
	void *context)
{
	struct bcm2708_dmachan *bcmchan = to_bcmchan(dmachan);

	dev_vdbg(bcmchan->dev, "%s: %d: %08x+%d [%d,%d] %p\n", __func__,
		bcmchan->id, buf_addr, buf_len, period_len, direction, context);

	return NULL;
}

static struct dma_async_tx_descriptor *bcm2708_dma_prep_interleaved_as_sg(
	struct dma_chan *dmachan, struct dma_interleaved_template *xt,
	unsigned long flags)
{
	struct scatterlist dst_sg;
	struct scatterlist src_sg;
	struct scatterlist *dst_tmp;
	struct scatterlist *src_tmp;
	unsigned int dst_nents = xt->numf * xt->frame_size;
	unsigned int src_nents = xt->numf * xt->frame_size;
	dma_addr_t src_addr = xt->src_start;
	dma_addr_t dst_addr = xt->dst_start;
	int i, j;

	sg_init_table(&dst_sg, dst_nents);
	sg_init_table(&src_sg, src_nents);
	dst_tmp = &dst_sg;
	src_tmp = &src_sg;

	for (i = 0; i < xt->numf; i++) {
		for (j = 0; j < xt->frame_size; j++) {
			if (i != 0 || j != 0) {
				dst_tmp = sg_next(dst_tmp);
				src_tmp = sg_next(src_tmp);
			}

			sg_dma_address(dst_tmp) = dst_addr;
			sg_dma_len(dst_tmp) = xt->sgl[j].size;

			sg_dma_address(src_tmp) = src_addr;
			sg_dma_len(src_tmp) = xt->sgl[j].size;

			dst_addr += (xt->sgl[j].size
				+ (xt->dst_sgl ? xt->sgl[j].icg : 0));
			src_addr += (xt->sgl[j].size
				+ (xt->src_sgl ? xt->sgl[j].icg : 0));
		}

		if (!xt->dst_inc)
			dst_addr = xt->dst_start;
		if (!xt->src_inc)
			src_addr = xt->src_start;
	}

	return bcm2708_dma_prep_dma_sg(dmachan,
		&dst_sg, dst_nents,
		&src_sg, src_nents, flags);
}

static struct dma_async_tx_descriptor *bcm2708_dma_prep_interleaved(
	struct dma_chan *dmachan, struct dma_interleaved_template *xt,
	unsigned long flags)
{
	struct bcm2708_dmachan *bcmchan = to_bcmchan(dmachan);	
	struct bcm2708_dmatx *bcmtx;
	u16 src_stride;
	u16 dst_stride;

	dev_vdbg(bcmchan->dev, "%s: %d: %p [%lu]\n", __func__,
		bcmchan->id, xt, flags);

	if (xt->frame_size == 0)
		return NULL;
	else if (xt->frame_size > 1)
		return bcm2708_dma_prep_interleaved_as_sg(dmachan, xt, flags);

	if (xt->sgl[0].size + xt->sgl[0].icg > MAX_STRIDE
			|| xt->numf > MAX_YLENGTH
			|| xt->sgl[0].size > MAX_XLENGTH)
		return bcm2708_dma_prep_interleaved_as_sg(dmachan, xt, flags);

	/* the engine also supports a negative icg, but this API doesn't */
	if (xt->sgl[0].size < 0)
		return NULL;

	bcmtx = bcm2708_dma_alloc_tx(bcmchan, flags, 1);
	if (unlikely(!bcmtx))
		return NULL;

	bcmtx->desc[0].cb->ti = BCM_TI_INTEN | BCM_TI_WAIT_RESP
		| BCM_TI_SRC_INC | BCM_TI_DST_INC | BCM_TI_TDMODE
		| BCM_TI_BURST_LEN_SET(BCM_TI_BURST_CHAN(bcmchan))
		| bcmchan->cfg;
	bcmtx->desc[0].cb->src = xt->src_start;
	bcmtx->desc[0].cb->dst = xt->dst_start;
	bcmtx->desc[0].cb->len = (xt->numf << 16) | xt->sgl[0].size;
	src_stride = !xt->src_inc ? 0 : (xt->sgl[0].size
		+ (xt->src_sgl ? xt->sgl[0].icg : 0));
	dst_stride = !xt->dst_inc ? 0 : (xt->sgl[0].size
		+ (xt->dst_sgl ? xt->sgl[0].icg : 0));
	bcmtx->desc[0].cb->stride = src_stride | (dst_stride << 16);

	spin_lock_irqsave(&bcmchan->prep_lock, flags);
	list_add_tail(&bcmtx->list, &bcmchan->prep_list);
	spin_unlock_irqrestore(&bcmchan->prep_lock, flags);
	return &bcmtx->dmatx;
}

static enum dma_status bcm2708_dma_tx_status(struct dma_chan *dmachan,
	dma_cookie_t cookie, struct dma_tx_state *txstate)
{
	return dma_cookie_status(dmachan, cookie, txstate);
}

static void __bcm2708_dma_issue_pending(struct bcm2708_dmachan *bcmchan)
{
	struct bcm2708_dmatx *bcmtx;

	if (bcmchan->active || list_empty(&bcmchan->pending))
		return;

	dev_vdbg(bcmchan->dev, "%s: %d\n", __func__, bcmchan->id);

	list_splice_tail_init(&bcmchan->pending, &bcmchan->running);
	bcmtx = list_first_entry(&bcmchan->running, struct bcm2708_dmatx, list);

	dsb();
	writel(bcmtx->dmatx.phys, bcmchan->base + REG_CONBLK_AD);
	writel(BCM_CS_ACTIVE, bcmchan->base + REG_CS);

	bcmchan->active = true;
}

static void bcm2708_dma_issue_pending(struct dma_chan *dmachan)
{
	struct bcm2708_dmachan *bcmchan = to_bcmchan(dmachan);
	unsigned long flags;

	spin_lock_irqsave(&bcmchan->lock, flags);
	__bcm2708_dma_issue_pending(bcmchan);
	spin_unlock_irqrestore(&bcmchan->lock, flags);
}

static void bcm2708_dma_update_progress(struct bcm2708_dmachan *bcmchan,
	u32 block, bool issue)
{
	struct bcm2708_dmatx *bcmtx;
	struct bcm2708_dmatx *tmp;
	struct bcm2708_dmatx *last = NULL;
	int i;

	dev_vdbg(bcmchan->dev, "%s: %d: %08x %d\n", __func__,
		bcmchan->id, block, issue);

	if (block == 0)
		bcmchan->active = false;

	list_for_each_entry_safe(bcmtx, tmp, &bcmchan->running, list) {
		if (block != 0) {
			for (i = 0; i < bcmtx->count; i++)
				if (block == bcmtx->desc[i].phys)
					goto done;
		}

		dma_cookie_complete(&bcmtx->dmatx);
		last = bcmtx;
	}

done:
	if (last != NULL) {
		LIST_HEAD(completed);
		list_cut_position(&completed, &bcmchan->running, &last->list);
		list_splice_tail(&completed, &bcmchan->completed);
	}
	if (issue)
		__bcm2708_dma_issue_pending(bcmchan);
	tasklet_schedule(&bcmchan->tasklet);
}

static inline void __bcm2708_dma_cleanup_dst(struct bcm2708_dmachan *bcmchan,
	struct bcm2708_dmatx *bcmtx, int i)
{
	if (bcmtx->dmatx.flags & DMA_COMPL_DEST_UNMAP_SINGLE)
		dma_unmap_single(bcmchan->dev, bcmtx->desc[i].cb->dst,
			bcmtx->desc[i].cb->len, DMA_FROM_DEVICE);
	else
		dma_unmap_page(bcmchan->dev, bcmtx->desc[i].cb->dst,
			bcmtx->desc[i].cb->len, DMA_FROM_DEVICE);
}

static inline void __bcm2708_dma_cleanup_src(struct bcm2708_dmachan *bcmchan,
	struct bcm2708_dmatx *bcmtx, int i)
{
	if (bcmtx->dmatx.flags & DMA_COMPL_SRC_UNMAP_SINGLE)
		dma_unmap_single(bcmchan->dev, bcmtx->desc[i].cb->src,
			bcmtx->desc[i].cb->len, DMA_TO_DEVICE);
	else
		dma_unmap_page(bcmchan->dev, bcmtx->desc[i].cb->src,
			bcmtx->desc[i].cb->len, DMA_TO_DEVICE);
}

static void __bcm2708_dma_cleanup(struct bcm2708_dmachan *bcmchan,
	struct bcm2708_dmatx *bcmtx)
{
	int i;

	dev_vdbg(bcmtx->chan->dev, "%s: %d: %08x\n", __func__,
		bcmtx->chan->id, bcmtx->dmatx.cookie);

	if (bcmtx->dmatx.callback)
		bcmtx->dmatx.callback(bcmtx->dmatx.callback_param);

	if (!(bcmtx->dmatx.flags & DMA_COMPL_SKIP_DEST_UNMAP))
		for (i = 0; i < bcmtx->count; i++)
			__bcm2708_dma_cleanup_dst(bcmchan, bcmtx, i);

	if (!(bcmtx->dmatx.flags & DMA_COMPL_SKIP_SRC_UNMAP))
		for (i = 0; i < bcmtx->count; i++)
			__bcm2708_dma_cleanup_src(bcmchan, bcmtx, i);
}

static void bcm2708_dma_tasklet(unsigned long data)
{
	struct bcm2708_dmachan *bcmchan = (struct bcm2708_dmachan *)data;
	LIST_HEAD(completed);
	struct bcm2708_dmatx *bcmtx;
	struct bcm2708_dmatx *tmp;
	unsigned long flags;

	spin_lock_irqsave(&bcmchan->lock, flags);
	list_splice_tail_init(&bcmchan->completed, &completed);
	spin_unlock_irqrestore(&bcmchan->lock, flags);

	list_for_each_entry_safe(bcmtx, tmp, &completed, list) {
		__bcm2708_dma_cleanup(bcmchan, bcmtx);
		list_del(&bcmtx->list);
		bcm2708_dma_free_tx(bcmtx);
	}
}

static void bcm2708_dma_record_abort(struct bcm2708_dmachan *bcmchan, u32 block)
{
	struct bcm2708_dmatx *bcmtx;
	bool found = false;
	int i;

	spin_lock(&bcmchan->lock);
	if (!list_empty(&bcmchan->running)) {
		bcmtx = list_first_entry(&bcmchan->running,
				struct bcm2708_dmatx, list);

		for (i = 0; i < bcmtx->count; i++)
			if (block == bcmtx->desc[i].phys)
				found = true;

		if (found) {
			list_del(&bcmtx->list);
			list_add_tail(&bcmtx->list, &bcmchan->completed);
		}
	}
	spin_unlock(&bcmchan->lock);

	if (!found)
		dev_warn(bcmchan->dev, "unable to find CB in error\n");
}

/*
 * An optimised shared IRQ handler could be written that uses REG_INT_STATUS
 * to detect activity on channels that are sharing an IRQ
 */
static irqreturn_t bcm2708_dma_irq_handler(int irq, void *dev_id)
{
	struct bcm2708_dmachan *bcmchan = dev_id;
	u32 status = readl(bcmchan->base + REG_CS);
	u32 block;

	dev_vdbg(bcmchan->dev, "%s: %d: %08x\n", __func__,
		bcmchan->id, status);

	if (!(status & BCM_CS_INT))
		return IRQ_NONE;

	block = readl(bcmchan->base + REG_CONBLK_AD);

	if (status & BCM_CS_END) {
		writel(BCM_CS_END, bcmchan->base + REG_CS);
		spin_lock(&bcmchan->lock);
		bcm2708_dma_update_progress(bcmchan, block,
						!!(status & BCM_CS_ERROR));
		spin_unlock(&bcmchan->lock);
	}

	if (status & BCM_CS_ERROR) {
		u32 debug = readl(bcmchan->base + REG_DEBUG);

		dev_warn(bcmchan->dev, "error on chan %d:%s%s%s %08x at %08x\n",
			bcmchan->id,
			BCM_DEBUG_RLSN_ERR(debug) ? " rlsn" : "",
			BCM_DEBUG_FIFO_ERR(debug) ? " fifo" : "",
			BCM_DEBUG_READ_ERR(debug) ? " read" : "",
			BCM_DEBUG_DMA_STATE(debug),
			block);

		writel(BCM_DEBUG_RLSN_ERR(debug)
				| BCM_DEBUG_FIFO_ERR(debug)
				| BCM_DEBUG_READ_ERR(debug),
			bcmchan->base + REG_DEBUG);

		bcm2708_dma_record_abort(bcmchan, block);

		writel(BCM_CS_ABORT | BCM_CS_ACTIVE, bcmchan->base + REG_CS);
	}

	writel(BCM_CS_INT, bcmchan->base + REG_CS);
	return IRQ_HANDLED;
}

static int bcm2708_dma_control(struct dma_chan *dmachan,
		enum dma_ctrl_cmd cmd, unsigned long arg)
{
	struct bcm2708_dmachan *bcmchan = to_bcmchan(dmachan);
	struct dma_slave_config *slcfg;
	unsigned long flags;

	dev_vdbg(bcmchan->dev, "%s: %d: %d %lu\n", __func__,
		bcmchan->id, cmd, arg);

	switch (cmd) {
	case DMA_SLAVE_CONFIG:
		slcfg = (struct dma_slave_config *)arg;
		if (slcfg == NULL) {
			return -EINVAL;
		} else if (slcfg->direction == DMA_DEV_TO_MEM) {
			if ((slcfg->src_addr & PERIPHERAL_MASK)
					!= PERIPHERAL_BASE)
				return -EINVAL;
			if ((slcfg->dst_addr & PERIPHERAL_MASK)
					== PERIPHERAL_BASE)
				return -EINVAL;

			bcmchan->slcfg = *slcfg;
			bcmchan->slcfg.src_addr += PERIPHERAL_OFFSET;
			return 0;
		} else if (slcfg->direction == DMA_MEM_TO_DEV) {
			if ((slcfg->src_addr & PERIPHERAL_MASK)
					== PERIPHERAL_BASE)
				return -EINVAL;
			if ((slcfg->dst_addr & PERIPHERAL_MASK)
					!= PERIPHERAL_BASE)
				return -EINVAL;

			bcmchan->slcfg = *slcfg;

			bcmchan->slcfg.src_addr = slcfg->dst_addr;
			bcmchan->slcfg.src_addr_width = slcfg->dst_addr_width;
			bcmchan->slcfg.src_maxburst = slcfg->dst_maxburst;
			bcmchan->slcfg.src_addr += PERIPHERAL_OFFSET;

			bcmchan->slcfg.dst_addr = slcfg->src_addr;
			bcmchan->slcfg.dst_addr_width = slcfg->src_addr_width;
			bcmchan->slcfg.dst_maxburst = slcfg->src_maxburst;
			return 0;
		}
		return -EINVAL;

	case BCM2708DMA_CONFIG: {
		struct bcm2708_dmacfg *cfg = (struct bcm2708_dmacfg *)arg;

		if (cfg == NULL || cfg->waits > MAX_WAITS)
			return -EINVAL;

		bcmchan->cfg = bcm2708_dma_make_cfg(cfg);
		return 0;
	}

	case DMA_TERMINATE_ALL:
		spin_lock_irqsave(&bcmchan->prep_lock, flags);
		bcm2708_dma_delete(&bcmchan->prep_list);
		spin_unlock_irqrestore(&bcmchan->prep_lock, flags);

		spin_lock_irqsave(&bcmchan->lock, flags);
		if (bcmchan->active) {
			u32 block;

			if (!bcmchan->paused)
				writel(0, bcmchan->base + REG_CS);
			block = readl(bcmchan->base + REG_CONBLK_AD);

			bcm2708_dma_abort(bcmchan);
			bcm2708_dma_update_progress(bcmchan, block, false);
		}
		bcm2708_dma_delete(&bcmchan->pending);
		bcm2708_dma_delete(&bcmchan->running);
		spin_unlock_irqrestore(&bcmchan->lock, flags);
		return 0;

	case DMA_PAUSE:
		spin_lock_irqsave(&bcmchan->lock, flags);
		if (bcmchan->active && !bcmchan->paused) {
			writel(0, bcmchan->base + REG_CS);
			bcmchan->paused = true;
		}
		spin_unlock_irqrestore(&bcmchan->lock, flags);
		return 0;

	case DMA_RESUME:
		spin_lock_irqsave(&bcmchan->lock, flags);
		if (bcmchan->active && bcmchan->paused) {
			bcmchan->paused = false;
			writel(BCM_CS_ACTIVE, bcmchan->base + REG_CS);
		}
		spin_unlock_irqrestore(&bcmchan->lock, flags);
		return 0;

	default:
		return -ENOSYS;
	}
}

static int bcm2708_dma_probe(struct platform_device *pdev)
{
	struct device_node *np = pdev->dev.of_node;
	struct bcm2708_dmadev *bcmdev = devm_kzalloc(&pdev->dev,
		sizeof(*bcmdev), GFP_KERNEL);
	struct dma_device *dmadev = bcmdev->dmadev;
	struct bcm2708_dmachan *bcmchan;
	struct dma_chan *dmachan;
	unsigned int nr_chans;
	u32 channels;
	int ret, i;

	if (bcmdev == NULL)
		return -ENOMEM;
	bcmdev->dev = &pdev->dev;
	bcmdev->pool = dmam_pool_create(dev_name(bcmdev->dev), bcmdev->dev,
		sizeof(struct bcm2708_dmacb),
		sizeof(struct bcm2708_dmacb), 32);
	if (!bcmdev->pool) {
		dev_err(bcmdev->dev, "unable to create dma pool\n");
		return -ENOMEM;
	}

	for (i = 0; i < 2; i++) {
		if (of_address_to_resource(np, i, &bcmdev->res[i])) {
			dev_err(bcmdev->dev, "missing resource %d\n", i);
			return -EINVAL;
		}

		if (resource_size(&bcmdev->res[i]) < SZ_4K) {
			dev_err(bcmdev->dev,
				"resource %d size too small (%#x)\n",
				i, resource_size(&bcmdev->res[i]));
			return -EINVAL;
		}

		bcmdev->base[i] = devm_request_and_ioremap(bcmdev->dev,
			&bcmdev->res[i]);
		if (!bcmdev->base[i]) {
			dev_err(bcmdev->dev, "error mapping io at %#lx\n",
				(unsigned long)bcmdev->res[i].start);
			return -EIO;
		}
	}

	if (of_property_read_u32(np, "broadcom,channels", &channels)) {
		dev_err(bcmdev->dev, "missing channels mask\n");
		return -EINVAL;
	}

	for (i = 0; i < D_MAX; i++) {
		dmadev[i].dev = bcmdev->dev;
		dmadev[i].chancnt = 0;
		INIT_LIST_HEAD(&dmadev[i].channels);
	}

	channels &= readl(bcmdev->base[0] + REG_ENABLE);

	for (i = 0; i < MAX_CHANS; i++) {
		u32 debug;
		char *tmp;
		int type, len;

		if (!(channels & BIT(i)))
			continue;

		bcmchan = devm_kzalloc(bcmdev->dev,
			sizeof(*bcmchan), GFP_KERNEL);
		if (bcmchan == NULL)
			return -ENOMEM;
		dmachan = &bcmchan->dmachan;
		bcmchan->dev = bcmdev->dev;
		bcmchan->pool = bcmdev->pool;
		bcmchan->id = i;
		spin_lock_init(&bcmchan->prep_lock);
		INIT_LIST_HEAD(&bcmchan->prep_list);
		spin_lock_init(&bcmchan->lock);
		INIT_LIST_HEAD(&bcmchan->pending);
		INIT_LIST_HEAD(&bcmchan->running);
		INIT_LIST_HEAD(&bcmchan->completed);
		tasklet_init(&bcmchan->tasklet, bcm2708_dma_tasklet,
			(unsigned long)bcmchan);

		/* valid only for channels 0 - 14
		 * 15 has its own base address
		 */
		if (bcmchan->id == 15)
			bcmchan->base = bcmdev->base[1];
		else
			bcmchan->base = bcmdev->base[0] + i * SZ_256;

		debug = readl(bcmchan->base + REG_DEBUG);
		bcmchan->axi_id = BCM_DEBUG_DMA_ID(debug);
		bcmchan->version = BCM_DEBUG_VERSION(debug);
		bcmchan->lite = BCM_DEBUG_LITE(debug);
		writel(BCM_CS_RESET, bcmchan->base + REG_CS);

		bcmchan->irq = irq_of_parse_and_map(np, i);
		if (!bcmchan->irq) {
			devm_kfree(bcmdev->dev, bcmchan);
			continue;
		}

		len = strlen(dev_name(bcmdev->dev)) + 16;
		tmp = devm_kzalloc(bcmdev->dev, len, GFP_KERNEL);
		if (!tmp) {
			devm_kfree(bcmdev->dev, bcmchan);
			continue;
		}
		snprintf(tmp, len, "%s:chan%d", dev_name(bcmdev->dev), i);

		ret = devm_request_irq(bcmdev->dev, bcmchan->irq,
			bcm2708_dma_irq_handler, IRQF_SHARED, tmp, bcmchan);
		if (ret) {
			devm_kfree(bcmdev->dev, tmp);
			devm_kfree(bcmdev->dev, bcmchan);
			continue;
		}

		dma_cookie_init(dmachan);
		type = bcmchan->lite ? D_LITE : D_FULL;
		dmachan->device = &dmadev[type];

		list_add_tail(&dmachan->device_node, &dmadev[type].channels);
		dmadev[type].chancnt++;
	}

	nr_chans = dmadev[D_FULL].chancnt + dmadev[D_LITE].chancnt;
	if (nr_chans == 0) {
		dev_err(bcmdev->dev, "no usable channels\n");
		return -ENXIO;
	}

	dma_cap_set(DMA_MEMCPY, dmadev[D_FULL].cap_mask);
	dma_cap_set(DMA_MEMSET, dmadev[D_FULL].cap_mask);
	dma_cap_set(DMA_INTERRUPT, dmadev[D_FULL].cap_mask);
	dma_cap_set(DMA_SLAVE, dmadev[D_FULL].cap_mask);
	dma_cap_set(DMA_SG, dmadev[D_FULL].cap_mask);
	/* TODO: dma_cap_set(DMA_CYCLIC, dmadev[D_FULL].cap_mask); */
	dma_cap_set(DMA_INTERLEAVE, dmadev[D_FULL].cap_mask);

	dma_cap_set(DMA_MEMCPY, dmadev[D_LITE].cap_mask);
	dma_cap_set(DMA_INTERRUPT, dmadev[D_LITE].cap_mask);
	dma_cap_set(DMA_SG, dmadev[D_LITE].cap_mask);

	for (i = 0; i < D_MAX; i++) {
		if (list_empty(&dmadev[i].channels))
			continue;

		dmadev[i].copy_align = 1;
		dmadev[i].fill_align = 1;

		dmadev[i].device_alloc_chan_resources = bcm2708_dma_alloc_chan;
		dmadev[i].device_free_chan_resources = bcm2708_dma_free_chan;

		dmadev[i].device_prep_dma_memcpy = bcm2708_dma_prep_memcpy;
		dmadev[i].device_prep_dma_interrupt = bcm2708_dma_prep_interrupt;
		dmadev[i].device_prep_dma_sg = bcm2708_dma_prep_dma_sg;
		if (i != D_LITE) {
			dmadev[i].device_prep_dma_memset = bcm2708_dma_prep_memset;
			dmadev[i].device_prep_slave_sg = bcm2708_dma_prep_slave_sg;
			dmadev[i].device_prep_dma_cyclic = bcm2708_dma_prep_cyclic;
			dmadev[i].device_prep_interleaved_dma = bcm2708_dma_prep_interleaved;
		}
		dmadev[i].device_control = bcm2708_dma_control;

		dmadev[i].device_tx_status = bcm2708_dma_tx_status;
		dmadev[i].device_issue_pending = bcm2708_dma_issue_pending;

		ret = dma_async_device_register(&dmadev[i]);
		if (ret) {
			dev_err(bcmdev->dev,
				"unable to register device %d (%d)\n", i, ret);
			while (--i >= 0)
				dma_async_device_unregister(&bcmdev->dmadev[i]);
			return ret;
		}
	}

	dev_info(bcmdev->dev, "%u channel%s at MMIO %#lx, %#lx\n",
		nr_chans, nr_chans != 1 ? "s" : "",
		(unsigned long)bcmdev->res[0].start,
		(unsigned long)bcmdev->res[1].start);

	for (i = 0; i < D_MAX; i++) {
		list_for_each_entry(dmachan,
				&dmadev[i].channels, device_node) {
			bcmchan = to_bcmchan(dmachan);
			dev_dbg(bcmdev->dev,
				"channel %d, (irq = %d) 0x%02x v%d%s\n",
				bcmchan->id, bcmchan->irq,
				bcmchan->axi_id, bcmchan->version,
				bcmchan->lite ? " [lite]" : "");
		}
	}

	platform_set_drvdata(pdev, bcmdev);
	return 0;
}

static int bcm2708_dma_remove(struct platform_device *pdev)
{
	struct bcm2708_dmadev *bcmdev = platform_get_drvdata(pdev);
	struct dma_chan *dmachan;
	struct bcm2708_dmachan *bcmchan;
	int i;

	for (i = 0; i < D_MAX; i++) {
		if (list_empty(&bcmdev->dmadev[i].channels))
			continue;

		list_for_each_entry(dmachan,
				&bcmdev->dmadev[i].channels, device_node) {
			bcmchan = to_bcmchan(dmachan);
			tasklet_kill(&bcmchan->tasklet);
		}

		dma_async_device_unregister(&bcmdev->dmadev[i]);
	}
	platform_set_drvdata(pdev, NULL);
	return 0;
}

static struct of_device_id bcm2708_dma_match[] __devinitconst = {
	{ .compatible = "broadcom,bcm2708-dma" },
	{}
};
MODULE_DEVICE_TABLE(of, bcm2708_dma_match);

static struct platform_driver bcm2708_dma_driver = {
	.probe	= bcm2708_dma_probe,
	.remove	= bcm2708_dma_remove,
	.driver	= {
		.name = MODULE_NAME,
		.owner = THIS_MODULE,
		.of_match_table = bcm2708_dma_match
	}
};
module_platform_driver(bcm2708_dma_driver);

MODULE_AUTHOR("Simon Arlott");
MODULE_DESCRIPTION("Broadcom BCM2708 DMA engine driver");
MODULE_LICENSE("GPL");
