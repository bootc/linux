/*
 * Driver for Broadcom BCM2708 BSC Controllers
 *
 * Copyright (C) 2012 Chris Boot & Frank Buss
 *
 * This driver is inspired by:
 * i2c-ocores.c, by Peter Korsgaard <jacmet@sunsite.dk>
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
#include <linux/slab.h>
#include <linux/i2c.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/of_platform.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/of_i2c.h>
#include <linux/pinctrl/consumer.h>

/* BSC register offsets */
#define BSC_C			0x00
#define BSC_S			0x04
#define BSC_DLEN		0x08
#define BSC_A			0x0c
#define BSC_FIFO		0x10
#define BSC_DIV			0x14
#define BSC_DEL			0x18
#define BSC_CLKT		0x1c

/* Bitfields in BSC_C */
#define BSC_C_I2CEN		0x00008000
#define BSC_C_INTR		0x00000400
#define BSC_C_INTT		0x00000200
#define BSC_C_INTD		0x00000100
#define BSC_C_ST		0x00000080
#define BSC_C_CLEAR_1		0x00000020
#define BSC_C_CLEAR_2		0x00000010
#define BSC_C_READ		0x00000001

/* Bitfields in BSC_S */
#define BSC_S_CLKT		0x00000200
#define BSC_S_ERR		0x00000100
#define BSC_S_RXF		0x00000080
#define BSC_S_TXE		0x00000040
#define BSC_S_RXD		0x00000020
#define BSC_S_TXD		0x00000010
#define BSC_S_RXR		0x00000008
#define BSC_S_TXW		0x00000004
#define BSC_S_DONE		0x00000002
#define BSC_S_TA		0x00000001

#define I2C_CLOCK_HZ	100000	/* default if no clock-frequency in DT */
#define I2C_TIMEOUT_MS	150

#define DRV_NAME	"bcm2708_i2c"

struct bcm2708_i2c {
	struct i2c_adapter adapter;

	spinlock_t lock;
	void __iomem *base;
	struct clk *clk;

	struct completion done;

	struct i2c_msg *msg;
	int pos;
	int nmsgs;
	bool error;
};

static inline u32 bcm2708_rd(struct bcm2708_i2c *bi, unsigned reg)
{
	return readl(bi->base + reg);
}

static inline void bcm2708_wr(struct bcm2708_i2c *bi, unsigned reg, u32 val)
{
	writel(val, bi->base + reg);
}

static inline void bcm2708_bsc_reset(struct bcm2708_i2c *bi)
{
	bcm2708_wr(bi, BSC_C, 0);
	bcm2708_wr(bi, BSC_S, BSC_S_CLKT | BSC_S_ERR | BSC_S_DONE);	
}

static inline void bcm2708_bsc_fifo_drain(struct bcm2708_i2c *bi)
{
	while ((bcm2708_rd(bi, BSC_S) & BSC_S_RXD) && (bi->pos < bi->msg->len))
		bi->msg->buf[bi->pos++] = bcm2708_rd(bi, BSC_FIFO);
}

static inline void bcm2708_bsc_fifo_fill(struct bcm2708_i2c *bi)
{
	while ((bcm2708_rd(bi, BSC_S) & BSC_S_TXD) && (bi->pos < bi->msg->len))
		bcm2708_wr(bi, BSC_FIFO, bi->msg->buf[bi->pos++]);
}

static inline void bcm2708_bsc_setup(struct bcm2708_i2c *bi)
{
	u32 c = BSC_C_I2CEN | BSC_C_INTD | BSC_C_ST | BSC_C_CLEAR_1;

	if (bi->msg->flags & I2C_M_RD)
		c |= BSC_C_INTR | BSC_C_READ;
	else
		c |= BSC_C_INTT;

	bcm2708_wr(bi, BSC_A, bi->msg->addr);
	bcm2708_wr(bi, BSC_DLEN, bi->msg->len);
	bcm2708_wr(bi, BSC_C, c);
}

static irqreturn_t bcm2708_i2c_interrupt(int irq, void *dev_id)
{
	struct bcm2708_i2c *bi = dev_id;
	bool handled = true;
	u32 s;

	spin_lock(&bi->lock);

	s = bcm2708_rd(bi, BSC_S);

	if (s & (BSC_S_CLKT | BSC_S_ERR)) {
		bcm2708_bsc_reset(bi);
		bi->error = true;

		/* wake up our bh */
		complete(&bi->done);
	} else if (s & BSC_S_DONE) {
		bi->nmsgs--;

		if (bi->msg->flags & I2C_M_RD)
			bcm2708_bsc_fifo_drain(bi);

		bcm2708_bsc_reset(bi);

		if (bi->nmsgs) {
			/* advance to next message */
			bi->msg++;
			bi->pos = 0;
			bcm2708_bsc_setup(bi);
		} else {
			/* wake up our bh */
			complete(&bi->done);
		}
	} else if (s & BSC_S_TXW) {
		bcm2708_bsc_fifo_fill(bi);
	} else if (s & BSC_S_RXR) {
		bcm2708_bsc_fifo_drain(bi);
	} else {
		handled = false;
	}

	spin_unlock(&bi->lock);

	return handled ? IRQ_HANDLED : IRQ_NONE;
}

static int bcm2708_i2c_master_xfer(struct i2c_adapter *adap,
	struct i2c_msg *msgs, int num)
{
	struct bcm2708_i2c *bi = adap->algo_data;
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&bi->lock, flags);

	INIT_COMPLETION(bi->done);
	bi->msg = msgs;
	bi->pos = 0;
	bi->nmsgs = num;
	bi->error = false;

	spin_unlock_irqrestore(&bi->lock, flags);

	bcm2708_bsc_setup(bi);

	ret = wait_for_completion_timeout(&bi->done,
			msecs_to_jiffies(I2C_TIMEOUT_MS));
	if (ret == 0) {
		dev_err(&adap->dev, "transfer timed out\n");
		spin_lock_irqsave(&bi->lock, flags);
		bcm2708_bsc_reset(bi);
		spin_unlock_irqrestore(&bi->lock, flags);
		return -ETIMEDOUT;
	}

	return bi->error ? -EIO : num;
}

static u32 bcm2708_i2c_functionality(struct i2c_adapter *adap)
{
	return I2C_FUNC_I2C | /*I2C_FUNC_10BIT_ADDR |*/ I2C_FUNC_SMBUS_EMUL;
}

static struct i2c_algorithm bcm2708_i2c_algorithm = {
	.master_xfer = bcm2708_i2c_master_xfer,
	.functionality = bcm2708_i2c_functionality,
};

static int __devinit bcm2708_i2c_probe(struct platform_device *pdev)
{
	struct resource iomem;
	int irq, err = -ENOMEM;
	struct clk *clk;
	struct pinctrl *pctl;
	struct bcm2708_i2c *bi;
	struct i2c_adapter *adap;
	unsigned long clk_hz;
	u32 bus_hz;

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

	bi = devm_kzalloc(&pdev->dev, sizeof(*bi), GFP_KERNEL);
	if (!bi)
		return -ENOMEM;

	platform_set_drvdata(pdev, bi);

	adap = &bi->adapter;
	adap->algo = &bcm2708_i2c_algorithm;
	adap->algo_data = bi;
	adap->dev.parent = &pdev->dev;
	adap->dev.of_node = pdev->dev.of_node;
	strlcpy(adap->name, dev_name(&pdev->dev), sizeof(adap->name));

	spin_lock_init(&bi->lock);
	init_completion(&bi->done);

	bi->base = devm_request_and_ioremap(&pdev->dev, &iomem);
	if (!bi->base) {
		dev_err(&pdev->dev, "could not remap memory\n");
		return -EADDRNOTAVAIL;
	}

	bi->clk = clk;

	err = devm_request_irq(&pdev->dev, irq, bcm2708_i2c_interrupt,
			IRQF_SHARED, dev_name(&pdev->dev), bi);
	if (err) {
		dev_err(&pdev->dev, "could not request IRQ: %d\n", err);
		return err;
	}

	clk_prepare(clk);
	clk_hz = clk_get_rate(clk);

	err = of_property_read_u32(pdev->dev.of_node, "clock-frequency",
			&bus_hz);
	if (err) {
		bus_hz = I2C_CLOCK_HZ;
		dev_warn(&pdev->dev,
			"Missing parameter 'clock-frequency'; assuming %d KHz",
			bus_hz / 1000);
	}

	bcm2708_bsc_reset(bi);
	bcm2708_wr(bi, BSC_DIV, DIV_ROUND_UP(clk_hz, bus_hz));

	err = i2c_add_adapter(adap);
	if (err < 0) {
		dev_err(&pdev->dev, "could not add I2C adapter: %d\n", err);
		goto out_clk_unprepare;
	}

	dev_info(&pdev->dev, "BSC controller (irq %d)\n", irq);

	of_i2c_register_devices(adap);

	return 0;

out_clk_unprepare:
	clk_unprepare(clk);
	return err;
}

static int __devexit bcm2708_i2c_remove(struct platform_device *pdev)
{
	struct bcm2708_i2c *bi = platform_get_drvdata(pdev);

	platform_set_drvdata(pdev, NULL);

	i2c_del_adapter(&bi->adapter);
	clk_unprepare(bi->clk);

	return 0;
}

static const struct of_device_id bcm2708_i2c_match[] = {
	{ .compatible = "broadcom,bcm2708-i2c" },
	{},
};
MODULE_DEVICE_TABLE(of, bcm2708_i2c_match);

static struct platform_driver bcm2708_i2c_driver = {
	.driver		= {
		.name		= DRV_NAME,
		.owner		= THIS_MODULE,
		.of_match_table	= bcm2708_i2c_match,
	},
	.probe		= bcm2708_i2c_probe,
	.remove		= __devexit_p(bcm2708_i2c_remove),
};
module_platform_driver(bcm2708_i2c_driver);

MODULE_DESCRIPTION("BSC controller driver for Broadcom BCM2708");
MODULE_AUTHOR("Chris Boot <bootc@bootc.net>");
MODULE_LICENSE("GPL v2");
