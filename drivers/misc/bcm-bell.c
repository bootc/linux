/*
 * Copyright (C) 2010 Broadcom
 * Copyright 2012 Simon Arlott
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This device provides a shared mechanism for using the doorbells
 * shared between the ARM and the VideoCore processor.
 */

#include <linux/device.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/interrupt.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#include "bcm-bell.h"

#define MODULE_NAME "bcm-bell"

#define BELL_RING 0x4

struct bcm_bell {
	struct device *dev;
	struct resource res;
	void __iomem *base;
	bool read, write;

	/* used to lock open, handler and data */
	spinlock_t lock;
	bool open;
	void (*handler)(struct bcm_bell *, void *);
	void *data;

	u32 irq;
	struct irqaction irqaction;
};

static irqreturn_t bcm_bell_irq_handler(int irq, void *dev_id)
{
	unsigned long flags;
	struct bcm_bell *bell = dev_id;
	int status = readl(bell->base);

	if (status & BELL_RING) {
		void (*handler)(struct bcm_bell *, void *);
		void *data;

		spin_lock_irqsave(&bell->lock, flags);
		handler = bell->handler;
		data = bell->data;
		spin_unlock_irqrestore(&bell->lock, flags);

		if (handler)
			handler(bell, data);
		return IRQ_HANDLED;
	} else {
		return IRQ_NONE;
	}
}

static int __devinit bcm_bell_probe(struct platform_device *of_dev)
{
	struct device_node *node = of_dev->dev.of_node;
	struct bcm_bell *bell = kzalloc(sizeof(*bell), GFP_KERNEL);
	const char *access;
	int ret;

	if (bell == NULL)
		return -ENOMEM;

	bell->dev = &of_dev->dev;
	spin_lock_init(&bell->lock);

	if (of_address_to_resource(node, 0, &bell->res)) {
		ret = -EINVAL;
		goto err;
	}

	if (resource_size(&bell->res) < sizeof(u32)) {
		dev_err(bell->dev, "resource too small (%#x)\n",
			resource_size(&bell->res));
		ret = -EINVAL;
		goto err;
	}

	if (!request_region(bell->res.start, resource_size(&bell->res),
			node->full_name)) {
		dev_err(bell->dev, "resource %#lx unavailable\n",
			(unsigned long)bell->res.start);
		ret = -EBUSY;
		goto err;
	}

	bell->base = ioremap(bell->res.start, resource_size(&bell->res));
	if (!bell->base) {
		dev_err(bell->dev, "error mapping io at %#lx\n",
			(unsigned long)bell->res.start);
		ret = -EIO;
		goto err_release;
	}

	if (of_property_read_string(node, "access", &access)) {
		dev_err(bell->dev, "unable to read access configuration\n");
		ret = -EINVAL;
		goto err_unmap;
	}

	/* read this carefully so that the device tree format
	 * can be exended in the future
	 */
	bell->read = (access[0] == 'r');
	bell->write = (access[0] != '\0' && access[1] == 'w');
	if (bell->read && bell->write) {
		access = "r/w";
	} else if (bell->read) {
		access = "r/o";
	} else if (bell->write) {
		access = "w/o";
	} else {
		dev_err(bell->dev, "invalid access configuration: %s\n", access);
		ret = -EINVAL;
		goto err_unmap;
	}

	/* register the interrupt handler */
	if (bell->read) {
		bell->irq = irq_of_parse_and_map(node, 0);
		if (bell->irq <= 0) {
			dev_err(bell->dev, "no IRQ");
			spin_unlock_irq(&bell->lock);
			ret = -ENXIO;
			goto err_unmap;
		}
		bell->irqaction.name = dev_name(bell->dev);
		bell->irqaction.flags = IRQF_SHARED | IRQF_IRQPOLL;
		bell->irqaction.dev_id = bell;
		bell->irqaction.handler = bcm_bell_irq_handler;
		bell->handler = NULL;

		ret = setup_irq(bell->irq, &bell->irqaction);
		if (ret) {
			dev_err(bell->dev, "unable to setup irq %d", bell->irq);
			spin_unlock_irq(&bell->lock);
			goto err_unmap;
		}

		dev_info(bell->dev, "doorbell at MMIO %#lx (irq = %d, %s)\n",
			(unsigned long)bell->res.start, bell->irq, access);
	} else {
		dev_info(bell->dev, "doorbell at MMIO %#lx (%s)\n",
			(unsigned long)bell->res.start, access);
	}


	platform_set_drvdata(of_dev, bell);
	return 0;

err_unmap:
	iounmap(bell->base);
err_release:
	release_region(bell->res.start, resource_size(&bell->res));
err:
	kfree(bell);
	return ret;
}

static int bcm_bell_remove(struct platform_device *of_dev)
{
	struct bcm_bell *bell = platform_get_drvdata(of_dev);

	if (bell->read)
		remove_irq(bell->irq, &bell->irqaction);
	iounmap(bell->base);
	release_region(bell->res.start, resource_size(&bell->res));
	kfree(bell);
	platform_set_drvdata(of_dev, NULL);
	return 0;
}

struct bcm_bell *bcm_bell_get(struct device_node *node, const char *pbell)
{
	struct device_node *bell_node;
	struct platform_device *pdev;
	struct bcm_bell *bell;
	int ret;

	if (node == NULL || pbell == NULL)
		return ERR_PTR(-EINVAL);

	bell_node = of_parse_phandle(node, pbell, 0);
	if (bell_node == NULL)
		return ERR_PTR(-ENOENT);

	pdev = of_find_device_by_node(bell_node);
	if (pdev == NULL) {
		of_node_put(bell_node);
		return ERR_PTR(-ENODEV);
	}

	/* swap our node ref for a device ref */
	get_device(&pdev->dev);
	of_node_put(bell_node);

	if (pdev->dev.driver == NULL
			|| pdev->dev.driver->owner != THIS_MODULE) {
		ret = -ENODEV;
		goto put_dev;
	}

	bell = platform_get_drvdata(pdev);
	if (bell == NULL || bell->dev != &pdev->dev) {
		ret = -EINVAL;
		goto put_dev;
	}

	spin_lock_irq(&bell->lock);
	if (bell->open) {
		spin_unlock_irq(&bell->lock);
		ret = -EBUSY;
		goto put_dev;
	} else {
		bell->open = true;
	}
	spin_unlock_irq(&bell->lock);
	return bell;

put_dev:
	put_device(&pdev->dev);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(bcm_bell_get);

int bcm_bell_read(struct bcm_bell *bell,
	void (*handler)(struct bcm_bell *bell, void *data), void *data)
{
	if (bell == NULL || handler == NULL)
		return -EINVAL;

	if (!bell->read)
		return -EPERM;

	spin_lock_irq(&bell->lock);
	bell->handler = handler;
	bell->data = data;
	spin_unlock_irq(&bell->lock);

	if (handler == NULL)
		synchronize_irq(bell->irq);
	return 0;
}
EXPORT_SYMBOL_GPL(bcm_bell_read);

void bcm_bell_put(struct bcm_bell *bell)
{
	if (bell != NULL) {
		spin_lock_irq(&bell->lock);
		if (bell->read)
			bell->handler = NULL;
		bell->open = false;
		spin_unlock_irq(&bell->lock);

		if (bell->read)
			synchronize_irq(bell->irq);
		put_device(bell->dev);
	} else {
		WARN_ON(1);
	}
}
EXPORT_SYMBOL_GPL(bcm_bell_put);

int bcm_bell_write(struct bcm_bell *bell)
{
	if (bell == NULL)
		return -EINVAL;

	if (!bell->write)
		return -EPERM;

	writel(0, bell->base);
	return 0;
}
EXPORT_SYMBOL_GPL(bcm_bell_write);

static struct of_device_id bcm_bell_dt_match[] __devinitconst = {
	{ .compatible = "broadcom,bcm2708-bell" },
	{}
};
MODULE_DEVICE_TABLE(of, bcm_bell_dt_match);

static struct platform_driver bcm_bell_driver = {
	.probe = bcm_bell_probe,
	.remove = bcm_bell_remove,
	.driver = {
		.name = MODULE_NAME,
		.owner = THIS_MODULE,
		.of_match_table = bcm_bell_dt_match
	}
};

static int __init bcm_bell_init(void)
{
	int ret;
	printk(KERN_INFO MODULE_NAME ": Broadcom VideoCore Doorbell driver\n");

	ret = platform_driver_register(&bcm_bell_driver);
	if (ret)
		printk(KERN_ERR MODULE_NAME ": registration failed (%d)\n", ret);

	return ret;
}

static void __exit bcm_bell_exit(void)
{
	platform_driver_unregister(&bcm_bell_driver);
}

arch_initcall(bcm_bell_init);
module_exit(bcm_bell_exit);

MODULE_AUTHOR("Simon Arlott");
MODULE_DESCRIPTION("ARM doorbell I/O to VideoCore processor");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:bcm-bell");
