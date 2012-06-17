/*
 * Driver for Broadcom BCM2708 SPI Controllers
 *
 * Copyright (C) 2012 Chris Boot
 *
 * This driver is inspired by:
 * spi-ath79.c, Copyright (C) 2009-2011 Gabor Juhos <juhosg@openwrt.org>
 * spi-atmel.c, Copyright (C) 2006 Atmel Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/clk.h>
#include <linux/err.h>
#include <linux/platform_device.h>
#include <linux/io.h>
#include <linux/spi/spi.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/log2.h>
#include <linux/sched.h>
#include <linux/completion.h>
#include <linux/of_platform.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/pinctrl/consumer.h>

/* SPI register offsets */
#define SPI_CS			0x00
#define SPI_FIFO		0x04
#define SPI_CLK			0x08
#define SPI_DLEN		0x0c
#define SPI_LTOH		0x10
#define SPI_DC			0x14

/* Bitfields in CS */
#define SPI_CS_LEN_LONG		0x02000000
#define SPI_CS_DMA_LEN		0x01000000
#define SPI_CS_CSPOL2		0x00800000
#define SPI_CS_CSPOL1		0x00400000
#define SPI_CS_CSPOL0		0x00200000
#define SPI_CS_RXF		0x00100000
#define SPI_CS_RXR		0x00080000
#define SPI_CS_TXD		0x00040000
#define SPI_CS_RXD		0x00020000
#define SPI_CS_DONE		0x00010000
#define SPI_CS_LEN		0x00002000
#define SPI_CS_REN		0x00001000
#define SPI_CS_ADCS		0x00000800
#define SPI_CS_INTR		0x00000400
#define SPI_CS_INTD		0x00000200
#define SPI_CS_DMAEN		0x00000100
#define SPI_CS_TA		0x00000080
#define SPI_CS_CSPOL		0x00000040
#define SPI_CS_CLEAR_RX		0x00000020
#define SPI_CS_CLEAR_TX		0x00000010
#define SPI_CS_CPOL		0x00000008
#define SPI_CS_CPHA		0x00000004
#define SPI_CS_CS_10		0x00000002
#define SPI_CS_CS_01		0x00000001

#define SPI_TIMEOUT_MS	150
#define SPI_MODE_BITS	(SPI_CPOL | SPI_CPHA | SPI_CS_HIGH | SPI_NO_CS)

#define DRV_NAME	"bcm2708_spi"

struct bcm2708_spi {
	void __iomem *base;
	struct clk *clk;

	struct completion done;

	const u8 *tx_buf;
	u8 *rx_buf;
	int len;
};

static inline u32 bcm2708_rd(struct bcm2708_spi *bs, unsigned reg)
{
	return readl(bs->base + reg);
}

static inline void bcm2708_wr(struct bcm2708_spi *bs, unsigned reg, u32 val)
{
	writel(val, bs->base + reg);
}

static inline void bcm2708_rd_fifo(struct bcm2708_spi *bs, int len)
{
	u8 byte;

	while (len--) {
		byte = bcm2708_rd(bs, SPI_FIFO);
		if (bs->rx_buf)
			*bs->rx_buf++ = byte;
	}
}

static inline void bcm2708_wr_fifo(struct bcm2708_spi *bs, int len)
{
	u8 byte;

	if (len > bs->len)
		len = bs->len;

	while (len--) {
		byte = bs->tx_buf ? *bs->tx_buf++ : 0;
		bcm2708_wr(bs, SPI_FIFO, byte);
		bs->len--;
	}
}

static irqreturn_t bcm2708_spi_interrupt(int irq, void *dev_id)
{
	struct spi_master *master = dev_id;
	struct bcm2708_spi *bs = spi_master_get_devdata(master);
	u32 cs = bcm2708_rd(bs, SPI_CS);

	if (cs & SPI_CS_DONE) {
		if (bs->len) { /* first interrupt in a transfer */
			/* fill the TX fifo with up to 16 bytes */
			bcm2708_wr_fifo(bs, 16);
		} else { /* transfer complete */
			/* disable SPI interrupts */
			cs &= ~(SPI_CS_INTR | SPI_CS_INTD);
			bcm2708_wr(bs, SPI_CS, cs);

			/* wake up our bh */
			complete(&bs->done);
		}
	} else if (cs & SPI_CS_RXR) {
		/* read 12 bytes of data */
		bcm2708_rd_fifo(bs, 12);

		/* write up to 12 bytes */
		bcm2708_wr_fifo(bs, 12);
	}

	return IRQ_HANDLED;
}

static int bcm2708_spi_check_transfer(struct spi_device *spi,
		struct spi_transfer *tfr)
{
	u8 bpw;

	bpw = tfr ? tfr->bits_per_word : spi->bits_per_word;
	switch (bpw) {
	case 8:
		break;
	default:
		dev_err(&spi->dev, "unsupported bits_per_word=%d\n", bpw);
		return -EINVAL;
	}

	if (!(spi->mode & SPI_NO_CS) &&
			(spi->chip_select > spi->master->num_chipselect)) {
		dev_err(&spi->dev,
				"invalid chipselect %u\n",
				spi->chip_select);
		return -EINVAL;
	}

	return 0;
}

static int bcm2708_spi_start_transfer(struct spi_device *spi,
		struct spi_transfer *tfr)
{
	struct bcm2708_spi *bs = spi_master_get_devdata(spi->master);
	unsigned long spi_hz, clk_hz, cdiv;
	u32 cs = SPI_CS_INTR | SPI_CS_INTD | SPI_CS_TA;

	spi_hz = tfr->speed_hz ? tfr->speed_hz : spi->max_speed_hz;
	clk_hz = clk_get_rate(bs->clk);

	if (spi_hz >= clk_hz / 2) {
		cdiv = 2; /* clk_hz/2 is the fastest we can go */
	} else if (spi_hz) {
		/* CDIV must be a power of two */
		cdiv = roundup_pow_of_two(DIV_ROUND_UP(clk_hz, spi_hz));

		if (cdiv >= 65536)
			cdiv = 0; /* 0 is the slowest we can go */
	} else {
		cdiv = 0; /* 0 is the slowest we can go */
	}

	if (spi->mode & SPI_CPOL)
		cs |= SPI_CS_CPOL;
	if (spi->mode & SPI_CPHA)
		cs |= SPI_CS_CPHA;

	if (!(spi->mode & SPI_NO_CS)) {
		if (spi->mode & SPI_CS_HIGH) {
			cs |= SPI_CS_CSPOL;
			cs |= SPI_CS_CSPOL0 << spi->chip_select;
		}

		cs |= spi->chip_select;
	}

	INIT_COMPLETION(bs->done);
	bs->tx_buf = tfr->tx_buf;
	bs->rx_buf = tfr->rx_buf;
	bs->len = tfr->len;

	bcm2708_wr(bs, SPI_CLK, cdiv);
	bcm2708_wr(bs, SPI_CS, cs);

	return 0;
}

static int bcm2708_spi_finish_transfer(struct spi_device *spi,
		struct spi_transfer *tfr, bool cs_change)
{
	struct bcm2708_spi *bs = spi_master_get_devdata(spi->master);
	u32 cs = bcm2708_rd(bs, SPI_CS);

	/* drain RX FIFO */
	while (cs & SPI_CS_RXD) {
		bcm2708_rd_fifo(bs, 1);
		cs = bcm2708_rd(bs, SPI_CS);
	}

	if (tfr->delay_usecs)
		udelay(tfr->delay_usecs);

	if (cs_change)
		/* clear TA flag */
		bcm2708_wr(bs, SPI_CS, cs & ~SPI_CS_TA);

	return 0;
}

static int bcm2708_spi_setup(struct spi_device *spi)
{
	int ret;

	if (!spi->bits_per_word)
		spi->bits_per_word = 8;

	if (spi->mode & ~SPI_MODE_BITS) {
		dev_err(&spi->dev, "setup: unsupported mode bits %x\n",
				spi->mode & ~SPI_MODE_BITS);
		return -EINVAL;
	}

	ret = bcm2708_spi_check_transfer(spi, NULL);
	if (ret) {
		dev_err(&spi->dev, "setup: invalid message\n");
		return ret;
	}

	return 0;
}

static int bcm2708_spi_prepare_transfer(struct spi_master *master)
{
	return 0;
}

static int bcm2708_spi_transfer_one(struct spi_master *master,
		struct spi_message *mesg)
{
	struct bcm2708_spi *bs = spi_master_get_devdata(master);
	struct spi_transfer *tfr;
	struct spi_device *spi = mesg->spi;
	int err = 0;
	unsigned int timeout;
	bool cs_change;

	list_for_each_entry(tfr, &mesg->transfers, transfer_list) {
		if (!tfr->bits_per_word)
			tfr->bits_per_word = spi->bits_per_word;

		err = bcm2708_spi_check_transfer(spi, tfr);
		if (err)
			goto out;

		err = bcm2708_spi_start_transfer(spi, tfr);
		if (err)
			goto out;

		timeout = wait_for_completion_timeout(&bs->done,
				msecs_to_jiffies(SPI_TIMEOUT_MS));
		if (!timeout) {
			err = -ETIMEDOUT;
			goto out;
		}

		cs_change = tfr->cs_change ||
			list_is_last(&tfr->transfer_list, &mesg->transfers);

		err = bcm2708_spi_finish_transfer(spi, tfr, cs_change);
		if (err)
			goto out;

		mesg->actual_length += (tfr->len - bs->len);
	}

out:
	mesg->status = err;
	spi_finalize_current_message(master);

	return 0;
}

static int bcm2708_spi_unprepare_transfer(struct spi_master *master)
{
	return 0;
}

static int __devinit bcm2708_spi_probe(struct platform_device *pdev)
{
	struct resource iomem;
	int irq, err;
	struct clk *clk;
	struct pinctrl *pctl;
	struct spi_master *master;
	struct bcm2708_spi *bs;

	err = of_address_to_resource(pdev->dev.of_node, 0, &iomem);
	if (err) {
		dev_err(&pdev->dev, "could not get IO memory\n");
		return err;
	}

	irq = irq_of_parse_and_map(pdev->dev.of_node, 0);
	if (irq < 0) {
		dev_err(&pdev->dev, "could not get IRQ\n");
		return irq;
	}

	clk = devm_clk_get(&pdev->dev, "sys_pclk");
	if (IS_ERR(clk)) {
		dev_err(&pdev->dev, "could not find clk: %ld\n", PTR_ERR(clk));
		return PTR_ERR(clk);
	}

	pctl = devm_pinctrl_get_select_default(&pdev->dev);
	if (IS_ERR(pctl)) {
		dev_err(&pdev->dev, "could not set up pinctrl: %ld\n",
				PTR_ERR(pctl));
		return PTR_ERR(pctl);
	}

	master = spi_alloc_master(&pdev->dev, sizeof(*bs));
	if (!master) {
		dev_err(&pdev->dev, "spi_alloc_master() failed\n");
		return -ENOMEM;
	}

	/* the spi->mode bits understood by this driver: */
	master->mode_bits = SPI_MODE_BITS;

	master->bus_num = -1;
	master->num_chipselect = 3;
	master->setup = bcm2708_spi_setup;
	master->prepare_transfer_hardware = bcm2708_spi_prepare_transfer;
	master->transfer_one_message = bcm2708_spi_transfer_one;
	master->unprepare_transfer_hardware = bcm2708_spi_unprepare_transfer;

	master->dev.of_node = pdev->dev.of_node;
	platform_set_drvdata(pdev, master);

	master->rt = of_property_read_bool(pdev->dev.of_node,
			"linux,realtime");

	bs = spi_master_get_devdata(master);

	bs->base = devm_request_and_ioremap(&pdev->dev, &iomem);
	if (!bs->base) {
		dev_err(&pdev->dev, "could not remap memory\n");
		err = -EADDRNOTAVAIL;
		goto out_master_put;
	}

	init_completion(&bs->done);
	bs->clk = clk;

	err = devm_request_irq(&pdev->dev, irq, bcm2708_spi_interrupt, 0,
			dev_name(&pdev->dev), master);
	if (err) {
		dev_err(&pdev->dev, "could not request IRQ: %d\n", err);
		goto out_master_put;
	}

	/* initialise the hardware */
	clk_prepare(clk);
	bcm2708_wr(bs, SPI_CS, SPI_CS_CLEAR_RX | SPI_CS_CLEAR_TX);

	err = spi_register_master(master);
	if (err) {
		dev_err(&pdev->dev, "could not register SPI master: %d\n", err);
		goto out_clk_unprepare;
	}

	dev_info(&pdev->dev, "SPI controller (irq %d)\n", irq);

	return 0;

out_clk_unprepare:
	clk_unprepare(bs->clk);
out_master_put:
	spi_master_put(master);
	return err;
}

static int __devexit bcm2708_spi_remove(struct platform_device *pdev)
{
	struct spi_master *master = platform_get_drvdata(pdev);
	struct bcm2708_spi *bs = spi_master_get_devdata(master);

	spi_unregister_master(master);

	/* reset the hardware and block queue progress */
	bcm2708_wr(bs, SPI_CS, SPI_CS_CLEAR_RX | SPI_CS_CLEAR_TX);

	clk_unprepare(bs->clk);
	spi_master_put(master);

	return 0;
}

static const struct of_device_id bcm2708_spi_match[] __devinitconst = {
	{ .compatible = "broadcom,bcm2708-spi", },
	{}
};
MODULE_DEVICE_TABLE(of, bcm2708_spi_match);

static struct platform_driver bcm2708_spi_driver = {
	.driver		= {
		.name		= DRV_NAME,
		.owner		= THIS_MODULE,
		.of_match_table	= bcm2708_spi_match,
	},
	.probe		= bcm2708_spi_probe,
	.remove		= __devexit_p(bcm2708_spi_remove),
};
module_platform_driver(bcm2708_spi_driver);

MODULE_DESCRIPTION("SPI controller driver for Broadcom BCM2708");
MODULE_AUTHOR("Chris Boot <bootc@bootc.net>");
MODULE_LICENSE("GPL v2");
