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
#include <linux/spinlock.h>
#include <linux/clk.h>
#include <linux/err.h>
#include <linux/platform_device.h>
#include <linux/io.h>
#include <linux/spi/spi.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/log2.h>

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

#define DRV_NAME	"bcm2708_spi"

struct bcm2708_spi {
	spinlock_t lock;
	void __iomem *base;
	int irq;
	struct clk *clk;
	bool stopping;

	struct list_head queue;
	struct workqueue_struct *workq;
	struct work_struct work;
	/*wait_queue_head_t waitq;*/
};

struct bcm2708_spi_state {
	u32 cs;
	u16 cdiv;
};

static inline u32 bcm2708_rd(struct bcm2708_spi *bs, unsigned reg)
{
	return readl(bs->base + reg);
}

static inline void bcm2708_wr(struct bcm2708_spi *bs, unsigned reg, u32 val)
{
	writel(val, bs->base + reg);
}

static irqreturn_t bcm2708_spi_interrupt(int irq, void *dev_id)
{
	struct spi_master *master = dev_id;
	struct bcm2708_spi *bs = spi_master_get_devdata(master);

	spin_lock(&bs->lock);

	/* FIXME */

	spin_unlock(&bs->lock);

	return IRQ_NONE;
}

static int bcm2708_setup_state(struct spi_master *master,
		struct device *dev, struct bcm2708_spi_state *state,
		u32 hz, u8 csel, u8 mode, u8 bpw)
{
	struct bcm2708_spi *bs = spi_master_get_devdata(master);
	int cdiv;
	unsigned long bus_hz;
	u32 cs = 0;

	bus_hz = clk_get_rate(bs->clk);

	if (hz >= bus_hz) {
		cdiv = 2; /* bus_hz / 2 is as fast as we can go */
	} else if (hz) {
		cdiv = DIV_ROUND_UP(bus_hz, hz);

		/* CDIV must be a power of 2, so round up */
		cdiv = roundup_pow_of_two(cdiv);

		if (cdiv > 65536) {
			dev_dbg(dev,
				"setup: %d Hz too slow, cdiv %u; min %ld Hz\n",
				hz, cdiv, bus_hz / 65536);
			return -EINVAL;
		} else if (cdiv == 65536) {
			cdiv = 0;
		} else if (cdiv == 1) {
			cdiv = 2; /* 1 gets rounded down to 0; == 65536 */
		}
	} else {
		cdiv = 0;
	}

	switch (bpw) {
	case 8:
		break;
	default:
		dev_dbg(dev, "setup: invalid bits_per_word %u (must be 8)\n",
			bpw);
		return -EINVAL;
	}

	if (mode & SPI_CPOL)
		cs |= SPI_CS_CPOL;
	if (mode & SPI_CPHA)
		cs |= SPI_CS_CPHA;

	if (!(mode & SPI_NO_CS)) {
		if (mode & SPI_CS_HIGH) {
			cs |= SPI_CS_CSPOL;
			cs |= SPI_CS_CSPOL0 << csel;
		}

		cs |= csel;
	} else {
		cs |= SPI_CS_CS_10 | SPI_CS_CS_01;
	}

	if (state) {
		state->cs = cs;
		state->cdiv = cdiv;
	}

	return 0;
}

static int bcm2708_process_transfer(struct bcm2708_spi *bs,
		struct spi_message *msg, struct spi_transfer *xfer)
{
	struct spi_device *spi = msg->spi;
	struct bcm2708_spi_state state, *stp;
	int ret;
	const u8 *tx_buf;
	u8 *rx_buf, tmp;
	int tx_len, rx_len;
	u32 cs;

	if (bs->stopping)
		return -ESHUTDOWN;

	if (xfer->bits_per_word || xfer->speed_hz) {
		ret = bcm2708_setup_state(spi->master, &spi->dev, &state,
			spi->max_speed_hz, spi->chip_select, spi->mode,
			spi->bits_per_word);
		if (ret)
			return ret;

		stp = &state;
	} else {
		stp = spi->controller_state;
	}

	tx_buf = xfer->tx_buf;
	rx_buf = xfer->rx_buf;
	tx_len = rx_len = xfer->len;

	cs = stp->cs | SPI_CS_TA;

	bcm2708_wr(bs, SPI_CLK, stp->cdiv);
	bcm2708_wr(bs, SPI_CS, cs);

	while (tx_len || rx_len) {
		cs = bcm2708_rd(bs, SPI_CS);

		if (tx_len && (cs & SPI_CS_TXD)) {
			if (tx_buf)
				tmp = *tx_buf++;
			else
				tmp = 0;

			bcm2708_wr(bs, SPI_FIFO, tmp);
			tx_len--;
		}
		if (rx_len && (cs & SPI_CS_RXD)) {
			tmp = bcm2708_rd(bs, SPI_FIFO);
			rx_len--;

			if (rx_buf)
				*rx_buf++ = tmp;
		}
	}

	do {
		cs = bcm2708_rd(bs, SPI_CS);
	} while (!(cs & SPI_CS_DONE));

	if (xfer->delay_usecs)
		udelay(xfer->delay_usecs);

	if (list_is_last(&xfer->transfer_list, &msg->transfers) ||
			xfer->cs_change) {
		bcm2708_wr(bs, SPI_CS, cs & ~SPI_CS_TA);
	}

	msg->actual_length += xfer->len;

	return 0;
}

static void bcm2708_work(struct work_struct *work)
{
	struct bcm2708_spi *bs = container_of(work, struct bcm2708_spi, work);
	unsigned long flags;
	struct spi_message *msg;
	struct spi_transfer *xfer;
	int status = 0;

	spin_lock_irqsave(&bs->lock, flags);
	while (!list_empty(&bs->queue)) {
		msg = list_first_entry(&bs->queue, struct spi_message, queue);
		list_del_init(&msg->queue);
		spin_unlock_irqrestore(&bs->lock, flags);

		list_for_each_entry(xfer, &msg->transfers, transfer_list) {
			status = bcm2708_process_transfer(bs, msg, xfer);
			if (status)
				break;
		}

		msg->status = status;
		msg->complete(msg->context);

		spin_lock_irqsave(&bs->lock, flags);
	}
	spin_unlock_irqrestore(&bs->lock, flags);
}

static int bcm2708_spi_setup(struct spi_device *spi)
{
	struct bcm2708_spi *bs = spi_master_get_devdata(spi->master);
	struct bcm2708_spi_state *state;
	int ret;

	if (bs->stopping)
		return -ESHUTDOWN;

	if (!(spi->mode & SPI_NO_CS) &&
			(spi->chip_select > spi->master->num_chipselect)) {
		dev_dbg(&spi->dev,
			"setup: invalid chipselect %u (%u defined)\n",
			spi->chip_select, spi->master->num_chipselect);
		return -EINVAL;
	}

	state = spi->controller_state;
	if (!state) {
		state = kzalloc(sizeof(*state), GFP_KERNEL);
		if (!state)
			return -ENOMEM;

		spi->controller_state = state;
	}

	ret = bcm2708_setup_state(spi->master, &spi->dev, state,
		spi->max_speed_hz, spi->chip_select, spi->mode,
		spi->bits_per_word);
	if (ret < 0) {
		kfree(state);
		spi->controller_state = NULL;
	}

	dev_dbg(&spi->dev,
		"setup: cd %d: %d Hz, bpw %u, mode 0x%x -> CS=%08x CDIV=%04x\n",
		spi->chip_select, spi->max_speed_hz, spi->bits_per_word,
		spi->mode, state->cs, state->cdiv);

	return 0;
}

static int bcm2708_spi_transfer(struct spi_device *spi, struct spi_message *msg)
{
	struct bcm2708_spi *bs = spi_master_get_devdata(spi->master);
	struct spi_transfer *xfer;
	int ret;
	unsigned long flags;

	if (unlikely(list_empty(&msg->transfers)))
		return -EINVAL;

	if (bs->stopping)
		return -ESHUTDOWN;

	list_for_each_entry(xfer, &msg->transfers, transfer_list) {
		if (!(xfer->tx_buf || xfer->rx_buf) && xfer->len) {
			dev_dbg(&spi->dev, "missing rx or tx buf\n");
			return -EINVAL;
		}

		if (!xfer->bits_per_word || xfer->speed_hz)
			continue;

		ret = bcm2708_setup_state(spi->master, &spi->dev, NULL,
			xfer->speed_hz ? xfer->speed_hz : spi->max_speed_hz,
			spi->chip_select, spi->mode,
			xfer->bits_per_word ? xfer->bits_per_word :
				spi->bits_per_word);
		if (ret)
			return ret;
	}

	msg->status = -EINPROGRESS;
	msg->actual_length = 0;

	spin_lock_irqsave(&bs->lock, flags);
	list_add_tail(&msg->queue, &bs->queue);
	queue_work(bs->workq, &bs->work);
	spin_unlock_irqrestore(&bs->lock, flags);

	return 0;
}

static void bcm2708_spi_cleanup(struct spi_device *spi)
{
	if (spi->controller_state) {
		kfree(spi->controller_state);
		spi->controller_state = NULL;
	}
}

static int __devinit bcm2708_spi_probe(struct platform_device *pdev)
{
	struct resource *regs;
	int irq, err = -ENOMEM;
	struct clk *clk;
	struct spi_master *master;
	struct bcm2708_spi *bs;

	regs = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!regs) {
		dev_err(&pdev->dev, "could not get IO memory\n");
		return -ENXIO;
	}

	irq = platform_get_irq(pdev, 0);
	if (irq < 0) {
		dev_err(&pdev->dev, "could not get IRQ\n");
		return irq;
	}

	clk = clk_get(&pdev->dev, NULL);
	if (IS_ERR(clk)) {
		dev_err(&pdev->dev, "could not find clk: %ld\n", PTR_ERR(clk));
		return PTR_ERR(clk);
	}

	master = spi_alloc_master(&pdev->dev, sizeof(*bs));
	if (!master) {
		dev_err(&pdev->dev, "spi_alloc_master() failed\n");
		goto out_clk_put;
	}

	/* the spi->mode bits understood by this driver: */
	master->mode_bits = SPI_CPOL | SPI_CPHA | SPI_CS_HIGH | SPI_NO_CS;

	master->bus_num = pdev->id;
	master->num_chipselect = 3;
	master->setup = bcm2708_spi_setup;
	master->transfer = bcm2708_spi_transfer;
	master->cleanup = bcm2708_spi_cleanup;
	platform_set_drvdata(pdev, master);

	bs = spi_master_get_devdata(master);

	spin_lock_init(&bs->lock);
	INIT_LIST_HEAD(&bs->queue);
	/*init_waitqueue_head(&bs->waitq);*/
	INIT_WORK(&bs->work, bcm2708_work);

	bs->base = ioremap(regs->start, resource_size(regs));
	if (!bs->base) {
		dev_err(&pdev->dev, "could not remap memory\n");
		goto out_master_put;
	}

	bs->workq = create_singlethread_workqueue(dev_name(&pdev->dev));
	if (!bs->workq) {
		dev_err(&pdev->dev, "could not create workqueue\n");
		goto out_iounmap;
	}

	bs->irq = irq;
	bs->clk = clk;
	bs->stopping = false;

	err = request_irq(irq, bcm2708_spi_interrupt, 0, dev_name(&pdev->dev),
			master);
	if (err) {
		dev_err(&pdev->dev, "could not request IRQ: %d\n", err);
		goto out_workqueue;
	}

	/* initialise the hardware */
	clk_enable(clk);
	bcm2708_wr(bs, SPI_CS, SPI_CS_REN | SPI_CS_CLEAR_RX | SPI_CS_CLEAR_TX);

	err = spi_register_master(master);
	if (err) {
		dev_err(&pdev->dev, "could not register SPI master: %d\n", err);
		goto out_free_irq;
	}

	dev_info(&pdev->dev, "SPI Controller at 0x%08lx (irq %d)\n",
		(unsigned long)regs->start, irq);

	return 0;

out_free_irq:
	free_irq(bs->irq, master);
out_workqueue:
	destroy_workqueue(bs->workq);
out_iounmap:
	iounmap(bs->base);
out_master_put:
	spi_master_put(master);
out_clk_put:
	clk_put(clk);
	return err;
}

static int __devexit bcm2708_spi_remove(struct platform_device *pdev)
{
	struct spi_master *master = platform_get_drvdata(pdev);
	struct bcm2708_spi *bs = spi_master_get_devdata(master);

	/* reset the hardware and block queue progress */
	spin_lock_irq(&bs->lock);
	bs->stopping = true;
	bcm2708_wr(bs, SPI_CS, SPI_CS_CLEAR_RX | SPI_CS_CLEAR_TX);
	spin_unlock_irq(&bs->lock);

	flush_work_sync(&bs->work);

	clk_disable(bs->clk);
	clk_put(bs->clk);
	free_irq(bs->irq, master);
	iounmap(bs->base);

	spi_unregister_master(master);

	return 0;
}

static struct platform_driver bcm2708_spi_driver = {
	.driver		= {
		.name	= DRV_NAME,
		.owner	= THIS_MODULE,
	},
	.probe		= bcm2708_spi_probe,
	.remove		= __devexit_p(bcm2708_spi_remove),
};
module_platform_driver(bcm2708_spi_driver);

MODULE_DESCRIPTION("SPI controller driver for Broadcom BCM2708");
MODULE_AUTHOR("Chris Boot <bootc@bootc.net>");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:" DRV_NAME);
