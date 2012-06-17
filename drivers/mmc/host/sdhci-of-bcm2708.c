/*
 * Copyright 2010 Broadcom
 * Copyright 2012 Simon Arlott
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/bcm2708_dma.h>
#include <linux/bitops.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/dmaengine.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/platform_device.h>
#include <linux/slab.h>

#include "sdhci-pltfm.h"

#define REG_BOOT_TIMEOUT	0x70
#define REG_DBG_SEL		0x74
#define REG_EXRDFIFO_EN		0x80
#define REG_EXRDFIFO_CFG	0x84
#define REG_TUNE_STEP		0x88
#define REG_TUNE_STEPS_STD	0x8c
#define REG_TUNE_STEPS_DDR	0x90
#define REG_SPI_INT_SPT		0xf0

#ifdef CONFIG_MMC_SDHCI_OF_BCM2708_DMA
static bool use_dma = true;
module_param(use_dma, bool, 0400);
MODULE_PARM_DESC(use_dma, "Use slave DMA (default=1)");

static bool exrd_fifo = true;
module_param(exrd_fifo, bool, 0400);
MODULE_PARM_DESC(exrd_fifo, "Enable DMA extension data FIFO (default=1)");

static int rd_thrsh = 4;
module_param(rd_thrsh, int, 0400);
MODULE_PARM_DESC(rd_thrsh, "DMA extension data FIFO read threshold in 32-bit words (0-7)");
#endif

/* The Arasan has a bug whereby it may lose the content of
 * successive writes to registers that are within two SD-card clock
 * cycles of each other (a clock domain crossing problem).
 * It seems, however, that the data register does not have this problem.
 */
static void bcm2708_sdhci_clock_delay(struct sdhci_host *host, int reg)
{
	unsigned int ns_2clk;

	if (reg == SDHCI_BUFFER || host->clock == 0)
		return;

	/* host->clock is the clock freq in Hz */
	ns_2clk = 2000000000/host->clock;
	udelay(DIV_ROUND_UP(ns_2clk, 1000) + 1);
}

static void bcm2708_sdhci_writel(struct sdhci_host *host, u32 val, int reg)
{
	writel(val, host->ioaddr + reg);
	bcm2708_sdhci_clock_delay(host, reg);
}

static void bcm2708_sdhci_writew(struct sdhci_host *host, u16 val, int reg)
{
	writew(val, host->ioaddr + reg);
	bcm2708_sdhci_clock_delay(host, reg);
}

static void bcm2708_sdhci_writeb(struct sdhci_host *host, u8 val, int reg)
{
	writeb(val, host->ioaddr + reg);
	bcm2708_sdhci_clock_delay(host, reg);
}

static unsigned int bcm2708_sdhci_get_max_clock(struct sdhci_host *host)
{
	struct sdhci_pltfm_host *phost = sdhci_priv(host);
	return phost->clock;
}

#ifdef CONFIG_MMC_SDHCI_OF_BCM2708_DMA
static const struct bcm2708_dmacfg cfg = {
	.per = BCM2708_DMA_PER_EMMC
};

static bool bcm2708_sdhci_dma_filter(struct dma_chan *chan, void *filter_param)
{
	return dmaengine_device_control(chan,
			BCM2708DMA_CONFIG, (unsigned long)&cfg) == 0;
}

static struct dma_chan *bcm2708_sdhci_enable_slave_dma(struct sdhci_host *host)
{
	struct dma_chan *chan;
	dma_cap_mask_t mask;
	struct dma_slave_config slcfg = {
		.direction = DMA_DEV_TO_MEM,
		.src_addr_width = DMA_SLAVE_BUSWIDTH_4_BYTES,
		.src_maxburst = SZ_1K / DMA_SLAVE_BUSWIDTH_4_BYTES,
		.device_fc = true
	};
	struct resource *res;

	dma_cap_zero(mask);
	dma_cap_set(DMA_SLAVE, mask);

	res = platform_get_resource(to_platform_device(host->mmc->parent),
		IORESOURCE_MEM, 0);
	if (!res)
		return NULL;
	slcfg.src_addr = res->start + SDHCI_BUFFER;

	chan = dma_request_channel(mask, bcm2708_sdhci_dma_filter, NULL);

	if (dmaengine_device_control(chan,
			BCM2708DMA_CONFIG, (unsigned long)&cfg)) {
		dma_release_channel(chan);
		return NULL;
	}

	if (dmaengine_slave_config(chan, &slcfg)) {
		dma_release_channel(chan);
		return NULL;
	}

	bcm2708_sdhci_writel(host, exrd_fifo ? 1 : 0, REG_EXRDFIFO_EN);
	bcm2708_sdhci_writel(host, rd_thrsh & 7, REG_EXRDFIFO_CFG);

	return chan;
}
#endif

static struct sdhci_ops bcm2708_sdhci_ops __devinitconst = {
	.write_l = bcm2708_sdhci_writel,
	.write_w = bcm2708_sdhci_writew,
	.write_b = bcm2708_sdhci_writeb,

	.get_max_clock = bcm2708_sdhci_get_max_clock,
};

static struct sdhci_pltfm_data bcm2708_sdhci_pdata __devinitconst = {
	.quirks = SDHCI_QUIRK_BROKEN_CARD_DETECTION
		| SDHCI_QUIRK_DATA_TIMEOUT_USES_SDCLK
		| SDHCI_QUIRK_BROKEN_TIMEOUT_VAL
		| SDHCI_QUIRK_MISSING_CAPS
		| SDHCI_QUIRK_CAP_CLOCK_BASE_BROKEN,
	.quirks2 = SDHCI_QUIRK2_OCR_FROM_REGULATOR
		| SDHCI_QUIRK2_START_PIO_FROM_INT,
	.caps = SDHCI_CAN_DO_HISPD
};

static int __devinit bcm2708_sdhci_probe(struct platform_device *pdev)
{
	struct sdhci_pltfm_data *pdata = devm_kzalloc(&pdev->dev,
			sizeof(*pdata), GFP_KERNEL);
	struct sdhci_ops *ops = devm_kzalloc(&pdev->dev,
			sizeof(*ops), GFP_KERNEL);
	struct resource *res;
	void __iomem *base;

	*pdata = bcm2708_sdhci_pdata;
	*ops = bcm2708_sdhci_ops;
	pdata->ops = ops;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res)
		return -ENOMEM;
	base = devm_request_and_ioremap(&pdev->dev, res);
	if (!base)
		return -EIO;

	/* Disable extension data FIFO unless DMA is enabled */
	writel(0, base + REG_EXRDFIFO_EN);
	writel(0, base + REG_EXRDFIFO_CFG);
	devm_ioremap_release(&pdev->dev, base);
	devm_release_mem_region(&pdev->dev, res->start, resource_size(res));

#ifdef CONFIG_MMC_SDHCI_OF_BCM2708_DMA
	if (use_dma) {
		pdata->caps |= SDHCI_CAN_DO_SDMA;
		ops->enable_slave_dma = bcm2708_sdhci_enable_slave_dma;
	}
#endif

	return sdhci_pltfm_register(pdev, pdata);
}

static int __devexit bcm2708_sdhci_remove(struct platform_device *pdev)
{
	return sdhci_pltfm_unregister(pdev);
}

static struct of_device_id bcm2708_sdhci_match[] __devinitconst = {
	{ .compatible = "broadcom,bcm2708-sdhci" },
	{}
};
MODULE_DEVICE_TABLE(of, bcm2708_sdhci_match);

static struct platform_driver bcm2708_sdhci_driver = {
	.probe	= bcm2708_sdhci_probe,
	.remove	= __devexit_p(bcm2708_sdhci_remove),
	.driver	= {
		.name = "sdhci-of-bcm2708",
		.owner = THIS_MODULE,
		.of_match_table = bcm2708_sdhci_match,
		.pm = SDHCI_PLTFM_PMOPS
	}
};
module_platform_driver(bcm2708_sdhci_driver);

MODULE_AUTHOR("Simon Arlott");
MODULE_DESCRIPTION("Broadcom BCM2708 SDHCI driver");
MODULE_LICENSE("GPL");
