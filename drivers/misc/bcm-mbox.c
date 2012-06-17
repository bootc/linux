/*
 * Copyright (C) 2010 Broadcom
 * Copyright 2012 Simon Arlott
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This device provides a shared mechanism for writing to the mailbox
 * shared between the ARM and the VideoCore processor.
 *
 *
 * Use MBOX_STA_IRQ_DATA to get continuous interrupts when we have messages
 * to be read.
 *
 * Messages are received by the interrupt handler which adds them to a
 * per-channel inbox and then incrementing a semaphore.
 *
 * Messages are read by decrementing the per-channel semaphore and taking
 * them from the inbox list.
 *
 *
 * Use MBOX_STA_IRQ_WSPACE to get continuous interrupts when we can send
 * messages.
 *
 * Messages are written by adding them to the outbox list and enabling
 * the send interrupt (if not already enabled).
 *
 * Messages are sent by the interrupt handler which removes them from
 * the outbox and then disables the send interrupt (if there are no more
 * messages).
 */

#include <linux/bcm-mbox.h>
#include <linux/bitops.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/semaphore.h>
#include <linux/slab.h>
#include <linux/spinlock.h>


#define MODULE_NAME "bcm-mbox"

/* offsets from a mail box base address */
#define MBOX_RW		0x00	/* read/write next 4 words */
#define MBOX_POL	0x10	/* read without popping the fifo */
#define MBOX_SND	0x14	/* sender ID (bottom two bits) */
#define MBOX_STA	0x18	/* status */
#define MBOX_CNF	0x1c	/* configuration */
#define MBOX_OFF0	0x00	/* mailbox 0 */
#define MBOX_OFF1	0x20	/* mailbox 1 */
#define MBOX_REGSZ	0x40	/* total size for two mailboxes */
#define MAX_CHAN	0x0f	/* max channel index and mask for channel in message */
#define OF_CHANS_MASK	0x7fff	/* MAX_CHAN bits for device tree mask */

#define MBOX_MSG(chan, data28)	(((data28) & ~MAX_CHAN) | ((chan) & MAX_CHAN))
#define MBOX_CHAN(msg)		((msg) & MAX_CHAN)
#define MBOX_DATA28(msg)	((msg) & ~MAX_CHAN)

#define MBOX_STA_FULL		0x80000000
#define MBOX_STA_EMPTY		0x40000000
#define MBOX_STA_LEVEL		0x400000FF	/* Max. value depends on mailbox depth parameter */

#define MBOX_STA_IRQ_DATA	0x00000001	/* irq enable: this has data */
#define MBOX_STA_IRQ_WSPACE	0x00000002	/* irq enable: other has space */
#define MBOX_STA_IRQ_WEMPTY	0x00000004	/* irq enable: other is empty */
#define MBOX_STA_CLEAR_MSGS	0x00000008	/* clear msgs: write 1, then 0 */
#define MBOX_STA_HAS_DATA	0x00000010	/* irq pending: this has data */
#define MBOX_STA_HAS_WSPACE	0x00000020	/* irq pending: other has space */
#define MBOX_STA_HAS_WEMPTY	0x00000040	/* irq pending: other is empty */
/* Bit 7 is unused */
/* Writing anything to the status register clears the error bits */
#define MBOX_ERR_EACCESS	0x00000100	/* error: non-owner read from mailbox */
#define MBOX_ERR_OVERFLOW	0x00000200	/* error: write to full mailbox */
#define MBOX_ERR_UNDERFLOW	0x00000400	/* error: read from empty mailbox */
#define MBOX_ERR_MASK		0x00000700

struct bcm_mbox;

struct bcm_mbox_msg {
	struct list_head list;
	u32 val;
};

struct bcm_mbox_chan {
	struct bcm_mbox *mbox;
	int index;
};

struct bcm_mbox_store {
	/* used to lock open and inbox */
	spinlock_t lock;
	bool open;
	struct semaphore recv;
	struct list_head inbox;
};

struct bcm_mbox {
	struct device *dev;
	struct resource res;
	void __iomem *base;
	void __iomem *status;
	void __iomem *config;
	void __iomem *read;
	void __iomem *write;
	u32 irq;

	struct bcm_mbox_store store[MAX_CHAN+1];

	/* used to lock running, waiting, outbox
	 * and synchronise access to config
	 */
	spinlock_t lock;
	bool running;
	bool waiting;
	struct list_head outbox;
};

static inline struct bcm_mbox_store *to_mbox_store(struct bcm_mbox_chan *chan)
{
	return &chan->mbox->store[chan->index];
}

static void bcm_mbox_free(struct bcm_mbox *mbox)
{
	struct bcm_mbox_msg *msg;
	struct bcm_mbox_msg *tmp;
	int i;

	for (i = 0; i <= MAX_CHAN; i++) {
		list_for_each_entry_safe(msg, tmp,
				&mbox->store[i].inbox, list) {
			list_del(&msg->list);
			kfree(msg);
		}
	}

	list_for_each_entry_safe(msg, tmp, &mbox->outbox, list) {
		list_del(&msg->list);
		kfree(msg);
	}
}

static void bcm_mbox_irq_error(struct bcm_mbox *mbox, int error)
{
	dev_err(mbox->dev, "mailbox error %08x\n", error);

	/* clear it */
	spin_lock(&mbox->lock);
	if (mbox->running) {
		if (mbox->waiting) {
			writel(MBOX_STA_IRQ_DATA | MBOX_STA_IRQ_WSPACE,
				mbox->config);
		} else {
			writel(MBOX_STA_IRQ_DATA, mbox->config);
		}
	} else {
		writel(0, mbox->config);
	}
	spin_unlock(&mbox->lock);
}

static void bcm_mbox_irq_read(struct bcm_mbox *mbox)
{
	struct bcm_mbox_store *store;
	struct bcm_mbox_msg *msg;
	u32 val = readl(mbox->read);
	int index = MBOX_CHAN(val);

	store = &mbox->store[index];
	msg = kzalloc(sizeof(*msg), GFP_ATOMIC);

	if (msg == NULL) {
		dev_warn(mbox->dev,
			"out of memory: dropped message %08x\n", val);
		return;
	}

	msg->val = val | 0xf;
	dev_dbg(mbox->dev, "received message %08x\n", val);

	spin_lock(&store->lock);
	list_add_tail(&msg->list, &store->inbox);
	spin_unlock(&store->lock);
	up(&store->recv);
}

static bool bcm_mbox_irq_write(struct bcm_mbox *mbox)
{
	struct bcm_mbox_msg *msg;
	bool active = false;
	bool empty;

	spin_lock(&mbox->lock);
	if (list_empty(&mbox->outbox)) {
		msg = NULL;
		empty = true;
	} else {
		msg = list_first_entry(&mbox->outbox,
					struct bcm_mbox_msg, list);
		list_del(&msg->list);
		empty = list_empty(&mbox->outbox);
	}
	if (mbox->running && mbox->waiting && empty) {
		/* we don't want to send data, disable the interrupt */
		writel(MBOX_STA_IRQ_DATA, mbox->config);

		mbox->waiting = false;
	}
	spin_unlock(&mbox->lock);

	if (msg != NULL) {
		dev_dbg(mbox->dev, "sending message %08x\n", msg->val);
		writel(msg->val, mbox->write);
		kfree(msg);

		active = true;
	} else {
		dev_dbg(mbox->dev, "no message to send\n");
	}

	return active;
}

static irqreturn_t bcm_mbox_irq_handler(int irq, void *dev_id)
{
	struct bcm_mbox *mbox = dev_id;
	bool active = true;
	int ret = IRQ_NONE;
	int status;

	spin_lock(&mbox->lock);
	if (!mbox->running)
		active = false;
	spin_unlock(&mbox->lock);

	while (active) {
		status = readl(mbox->status);
		active = false;

		if (status & MBOX_ERR_MASK)
			bcm_mbox_irq_error(mbox, status & MBOX_ERR_MASK);

		if (!(status & MBOX_STA_EMPTY)) {
			/* we have data to read */
			bcm_mbox_irq_read(mbox);

			active = true;
			ret = IRQ_HANDLED;
		}

		if (!(status & MBOX_STA_FULL)) {
			/* we can send data */
			active = bcm_mbox_irq_write(mbox);
			ret = IRQ_HANDLED;
		}
	}

	return ret;
}

static int __devinit bcm_mbox_probe(struct platform_device *of_dev)
{
	struct device_node *node = of_dev->dev.of_node;
	struct bcm_mbox *mbox = devm_kzalloc(&of_dev->dev,
		sizeof(*mbox), GFP_KERNEL);
	int ret, i;
	unsigned long flags;

	if (mbox == NULL)
		return -ENOMEM;

	mbox->dev = &of_dev->dev;
	spin_lock_init(&mbox->lock);
	INIT_LIST_HEAD(&mbox->outbox);

	for (i = 0; i <= MAX_CHAN; i++) {
		sema_init(&mbox->store[i].recv, 0);
		spin_lock_init(&mbox->store[i].lock);
		INIT_LIST_HEAD(&mbox->store[i].inbox);
	}

	if (of_address_to_resource(node, 0, &mbox->res))
		return -EINVAL;

	if (resource_size(&mbox->res) < MBOX_REGSZ) {
		dev_err(mbox->dev, "resource too small (%#x)\n",
			resource_size(&mbox->res));
		return -EINVAL;
	}

	mbox->base = devm_request_and_ioremap(mbox->dev, &mbox->res);
	if (!mbox->base) {
		dev_err(mbox->dev, "error mapping io at %#lx\n",
			(unsigned long)mbox->res.start);
		return -EIO;
	}

	mbox->status = mbox->base + MBOX_OFF0 + MBOX_STA;
	mbox->config = mbox->base + MBOX_OFF0 + MBOX_CNF;
	mbox->read = mbox->base + MBOX_OFF0 + MBOX_RW;
	mbox->write = mbox->base + MBOX_OFF1 + MBOX_RW;

	/* disable interrupts and clear the mailbox */
	writel(0, mbox->config);
	writel(MBOX_STA_CLEAR_MSGS, mbox->config);
	writel(0, mbox->config);

	/* register the interrupt handler */
	mbox->irq = irq_of_parse_and_map(node, 0);
	if (mbox->irq <= 0) {
		dev_err(mbox->dev, "no IRQ");
		spin_unlock_irq(&mbox->lock);
		return -ENXIO;
	}

	mbox->running = false;
	mbox->waiting = false;

	ret = devm_request_irq(mbox->dev, mbox->irq, bcm_mbox_irq_handler,
		IRQF_SHARED, dev_name(mbox->dev), mbox);
	if (ret) {
		dev_err(mbox->dev, "unable to request irq %d", mbox->irq);
		spin_unlock_irq(&mbox->lock);
		return ret;
	}

	/* enable the interrupt on data reception */
	spin_lock_irqsave(&mbox->lock, flags);
	writel(MBOX_STA_IRQ_DATA, mbox->config);
	mbox->running = true;
	spin_unlock_irqrestore(&mbox->lock, flags);

	dev_info(mbox->dev, "mailbox at MMIO %#lx (irq = %d)\n",
		(unsigned long)mbox->res.start, mbox->irq);

	platform_set_drvdata(of_dev, mbox);
	return 0;
}

static int bcm_mbox_remove(struct platform_device *of_dev)
{
	struct bcm_mbox *mbox = platform_get_drvdata(of_dev);
	unsigned long flags;

	/* stop the interrupt handler */
	spin_lock_irqsave(&mbox->lock, flags);
	mbox->running = false;
	writel(0, mbox->config);
	spin_unlock_irqrestore(&mbox->lock, flags);

	/* wait for the interrupt handler to finish */
	synchronize_irq(mbox->irq);

	/* clear the mailbox */
	writel(MBOX_STA_CLEAR_MSGS, mbox->config);
	writel(0, mbox->config);
	bcm_mbox_free(mbox);

	platform_set_drvdata(of_dev, NULL);
	return 0;
}

struct bcm_mbox_chan *bcm_mbox_get(struct device_node *node,
	const char *pmbox, const char *pchan)
{
	struct device_node *mbox_node;
	struct platform_device *pdev;
	struct bcm_mbox *mbox;
	struct bcm_mbox_chan *chan;
	struct bcm_mbox_store *store;
	u32 index;
	int ret;
	unsigned long flags;

	if (node == NULL || pmbox == NULL || pchan == NULL)
		return ERR_PTR(-EINVAL);

	if (of_property_read_u32(node, pchan, &index))
		return ERR_PTR(-EINVAL);

	if (index > MAX_CHAN)
		return ERR_PTR(-EOVERFLOW);

	mbox_node = of_parse_phandle(node, pmbox, 0);
	if (mbox_node == NULL)
		return ERR_PTR(-ENOENT);

	pdev = of_find_device_by_node(mbox_node);
	if (pdev == NULL) {
		of_node_put(mbox_node);
		return ERR_PTR(-ENODEV);
	}

	/* swap our node ref for a device ref */
	get_device(&pdev->dev);
	of_node_put(mbox_node);

	if (pdev->dev.driver == NULL
			|| pdev->dev.driver->owner != THIS_MODULE) {
		ret = -ENODEV;
		goto put_dev;
	}

	mbox = platform_get_drvdata(pdev);
	if (mbox == NULL || mbox->dev != &pdev->dev) {
		ret = -EINVAL;
		goto put_dev;
	}

	/* check the channel is valid */
	if (index > MAX_CHAN) {
		ret = -ECHRNG;
		goto put_dev;
	}

	/* create a reference */
	chan = kmalloc(sizeof(*chan), GFP_KERNEL);
	if (chan == NULL) {
		ret = -ENOMEM;
		goto put_dev;
	}

	chan->mbox = mbox;
	chan->index = index;
	store = to_mbox_store(chan);

	spin_lock_irqsave(&store->lock, flags);
	if (store->open) {
		ret = -EBUSY;
		goto free_ref;
	} else {
		store->open = true;
	}
	spin_unlock_irqrestore(&store->lock, flags);
	return chan;

free_ref:
	kfree(chan);
put_dev:
	put_device(&pdev->dev);
	return ERR_PTR(ret);
}

static bool bcm_mbox_chan_valid(struct bcm_mbox_chan *chan)
{
	return chan != NULL && chan->mbox != NULL && chan->index <= MAX_CHAN;
}

char *bcm_mbox_name(struct bcm_mbox_chan *chan)
{
	if (!bcm_mbox_chan_valid(chan))
		return NULL;
	return kasprintf(GFP_KERNEL, "%s[%d]", dev_name(chan->mbox->dev),
		chan->index);
}
EXPORT_SYMBOL_GPL(bcm_mbox_name);

void bcm_mbox_put(struct bcm_mbox_chan *chan)
{
	if (bcm_mbox_chan_valid(chan)) {
		struct bcm_mbox_store *store = to_mbox_store(chan);
		unsigned long flags;

		spin_lock_irqsave(&store->lock, flags);
		WARN_ON(!store->open);
		store->open = false;
		spin_unlock_irqrestore(&store->lock, flags);

		put_device(chan->mbox->dev);
		kfree(chan);
	} else {
		WARN_ON(1);
	}
}

static void __bcm_mbox_write(struct bcm_mbox *mbox, struct bcm_mbox_msg *msg)
{
	int status;
	unsigned long flags;

	spin_lock_irqsave(&mbox->lock, flags);
	if (mbox->waiting) {
		list_add_tail(&msg->list, &mbox->outbox);
		goto out;
	}

	/* not waiting so the interrupt handler can't be sending */
	status = readl(mbox->status);

	if (!(status & MBOX_STA_FULL)) {
		/* we can send data */
		dev_dbg(mbox->dev, "sending message %08x\n", msg->val);
		writel(msg->val, mbox->write);
		kfree(msg);
	} else {
		list_add_tail(&msg->list, &mbox->outbox);

		/* enable the interrupt on write space available */
		writel(MBOX_STA_IRQ_DATA | MBOX_STA_IRQ_WSPACE, mbox->config);

		mbox->waiting = true;
	}
out:
	spin_unlock_irqrestore(&mbox->lock, flags);
}

int bcm_mbox_write(struct bcm_mbox_chan *chan, u32 data28)
{
	struct bcm_mbox *mbox;
	struct bcm_mbox_store *store;
	struct bcm_mbox_msg *msg;

	if (!bcm_mbox_chan_valid(chan))
		return -EINVAL;
	mbox = chan->mbox;
	store = to_mbox_store(chan);

	msg = kmalloc(sizeof(*msg), GFP_KERNEL);
	if (msg == NULL)
		return -ENOMEM;

	/* data shouldn't contain anything in the lower 4 bits */
	WARN_ON(data28 & MAX_CHAN);
	msg->val = MBOX_MSG(chan->index, data28);

	__bcm_mbox_write(mbox, msg);
	return 0;
}
EXPORT_SYMBOL_GPL(bcm_mbox_write);

static int __bcm_mbox_read(struct bcm_mbox_chan *chan, u32 *data28)
{
	struct bcm_mbox_store *store = to_mbox_store(chan);
	struct bcm_mbox_msg *msg;
	unsigned long flags;

	spin_lock_irqsave(&store->lock, flags);
	if (list_empty(&store->inbox)) {
		msg = NULL;
	} else {
		msg = list_first_entry(&store->inbox,
					struct bcm_mbox_msg, list);
		list_del(&msg->list);
	}
	spin_unlock_irqrestore(&store->lock, flags);
	WARN_ON(msg == NULL);

	if (msg != NULL) {
		*data28 = MBOX_DATA28(msg->val);
		kfree(msg);
		return 0;
	} else {
		return -EIO;
	}
}

int bcm_mbox_poll(struct bcm_mbox_chan *chan, u32 *data28)
{
	if (!bcm_mbox_chan_valid(chan))
		return -EINVAL;

	if (down_trylock(&to_mbox_store(chan)->recv))
		return -ENOENT;

	return __bcm_mbox_read(chan, data28);
}
EXPORT_SYMBOL_GPL(bcm_mbox_poll);

int bcm_mbox_read(struct bcm_mbox_chan *chan, u32 *data28)
{
	if (!bcm_mbox_chan_valid(chan))
		return -EINVAL;

	down(&to_mbox_store(chan)->recv);
	return __bcm_mbox_read(chan, data28);
}
EXPORT_SYMBOL_GPL(bcm_mbox_read);

int bcm_mbox_read_interruptible(struct bcm_mbox_chan *chan, u32 *data28)
{
	int ret;

	if (!bcm_mbox_chan_valid(chan))
		return -EINVAL;

	if ((ret = down_interruptible(&to_mbox_store(chan)->recv))) {
		/* The wait was interrupted */
		return ret;
	}

	return __bcm_mbox_read(chan, data28);
}
EXPORT_SYMBOL_GPL(bcm_mbox_read_interruptible);

int bcm_mbox_read_timeout(struct bcm_mbox_chan *chan, u32 *data28, long jiffies)
{
	int ret;

	if (!bcm_mbox_chan_valid(chan))
		return -EINVAL;

	if ((ret = down_timeout(&to_mbox_store(chan)->recv, jiffies))) {
		/* The wait was interrupted or timed out */
		return ret;
	}

	return __bcm_mbox_read(chan, data28);
}
EXPORT_SYMBOL_GPL(bcm_mbox_read_timeout);

int bcm_mbox_call(struct bcm_mbox_chan *chan, u32 out_data28, u32 *in_data28)
{
	int ret = bcm_mbox_write(chan, out_data28);
	if (ret)
		return ret;
	return bcm_mbox_read(chan, in_data28);
}
EXPORT_SYMBOL_GPL(bcm_mbox_call);

int bcm_mbox_call_interruptible(struct bcm_mbox_chan *chan, u32 out_data28,
	u32 *in_data28)
{
	int ret = bcm_mbox_write(chan, out_data28);
	if (ret)
		return ret;
	return bcm_mbox_read_interruptible(chan, in_data28);
}
EXPORT_SYMBOL_GPL(bcm_mbox_call_interruptible);

int bcm_mbox_call_timeout(struct bcm_mbox_chan *chan, u32 out_data28,
	u32 *in_data28, long jiffies)
{
	int ret = bcm_mbox_write(chan, out_data28);
	if (ret)
		return ret;
	return bcm_mbox_read_timeout(chan, in_data28, jiffies);
}
EXPORT_SYMBOL_GPL(bcm_mbox_call_timeout);

int bcm_mbox_clear(struct bcm_mbox_chan *chan)
{
	struct bcm_mbox_store *store;
	unsigned long flags;

	if (!bcm_mbox_chan_valid(chan))
		return -EINVAL;

	synchronize_irq(chan->mbox->irq);
	store = to_mbox_store(chan);

	while (!down_trylock(&store->recv)) {
		struct bcm_mbox_msg *msg;

		spin_lock_irqsave(&store->lock, flags);
		if (list_empty(&store->inbox)) {
			msg = NULL;
		} else {
			msg = list_first_entry(&store->inbox,
						struct bcm_mbox_msg, list);
			list_del(&msg->list);
		}
		spin_unlock_irqrestore(&store->lock, flags);
		WARN_ON(msg == NULL);

		if (msg != NULL)
			kfree(msg);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(bcm_mbox_clear);

static struct of_device_id bcm_mbox_dt_match[] __devinitconst = {
	{ .compatible = "broadcom,bcm2708-mbox" },
	{}
};
MODULE_DEVICE_TABLE(of, bcm_mbox_dt_match);

static struct platform_driver bcm_mbox_driver = {
	.probe = bcm_mbox_probe,
	.remove = bcm_mbox_remove,
	.driver = {
		.name = MODULE_NAME,
		.owner = THIS_MODULE,
		.of_match_table = bcm_mbox_dt_match
	}
};

static int __init bcm_mbox_init(void)
{
	printk(KERN_INFO MODULE_NAME ": Broadcom VideoCore Mailbox driver\n");

	return platform_driver_register(&bcm_mbox_driver);
}

static void __exit bcm_mbox_exit(void)
{
	platform_driver_unregister(&bcm_mbox_driver);
}

arch_initcall(bcm_mbox_init);
module_exit(bcm_mbox_exit);

MODULE_AUTHOR("Gray Girling, Simon Arlott");
MODULE_DESCRIPTION("ARM mailbox I/O to VideoCore processor");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:bcm-mbox");
