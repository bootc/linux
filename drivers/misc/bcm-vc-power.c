/*
 * Copyright (C) 2010 Broadcom
 * Copyright 2012 Simon Arlott
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This device provides a shared mechanism for using the power management
 * of the VideoCore processor.
 */

#include <linux/device.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/interrupt.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/slab.h>

#include "bcm-mbox.h"
#include "bcm-vc-power.h"

#define MODULE_NAME "bcm-vc-power"

/* 27 bits available in mbox (0-26) */
#define MAX_POWER_DEV 26
#define PMASK  0x07ffffff
#define PQUERY 0x08000000

#define PWR_TO_MBOX(x) ((x) << 4)
#define MBOX_TO_PWR(x) ((x) >> 4)

struct bcm_vc_power_mgr {
	struct device *dev;
	u32 valid;

	/* used to lock mbox, state */
	struct mutex lock;
	struct bcm_mbox_chan *mbox;
	u32 state;
	bool open[MAX_POWER_DEV];
};

struct bcm_vc_power_dev {
	struct bcm_vc_power_mgr *mgr;
	int index;
};

static int __devinit bcm_vc_power_mgr_probe(struct platform_device *of_dev)
{
	struct device_node *node = of_dev->dev.of_node;
	struct bcm_vc_power_mgr *mgr = kzalloc(sizeof(*mgr), GFP_KERNEL);
	u32 default_on;
	u32 default_off;
	char *name;
	int ret;

	if (mgr == NULL)
		return -ENOMEM;

	mgr->dev = &of_dev->dev;
	mutex_init(&mgr->lock);
	mgr->mbox = bcm_mbox_get(node, "broadcom,vc-mailbox", "broadcom,vc-channel");

	if (!mgr->mbox) {
		dev_err(mgr->dev, "unable to find mailbox channel\n");
		ret = -ENOENT;
		goto err;
	}

	mgr->valid = ~0;
	of_property_read_u32(node, "mask", &mgr->valid);
	mgr->valid &= PMASK;

	name = bcm_mbox_name(mgr->mbox);
	dev_info(mgr->dev, "attached to mailbox %s\n", name);
	kfree(name);

	dev_dbg(mgr->dev, "devices = %08x\n", mgr->valid);

	/* find out what is powered on */
	bcm_mbox_clear(mgr->mbox);
	ret = bcm_mbox_call_interruptible(mgr->mbox, PQUERY, &mgr->state);
	mgr->state = MBOX_TO_PWR(mgr->state) & PMASK;
	if (ret)
		goto err;

	dev_dbg(mgr->dev, "current = %08x\n", mgr->state);

	/* power on device defaults */
	if (!of_property_read_u32(node, "default-on", &default_on)) {
		struct bcm_vc_power_dev tmp = { .mgr = mgr };
		int i;

		dev_dbg(mgr->dev, "default-on = %08x\n", default_on);

		default_on &= mgr->valid;
		for (i = 0; i <= MAX_POWER_DEV; i++) {
			if (default_on & BIT(i)) {
				tmp.index = i;
				bcm_vc_power_on(&tmp);
			}
		}
	}
	if (!of_property_read_u32(node, "default-off", &default_off)) {
		struct bcm_vc_power_dev tmp = { .mgr = mgr };
		int i;

		dev_dbg(mgr->dev, "default-off = %08x\n", default_off);

		default_off &= mgr->valid;
		for (i = 0; i <= MAX_POWER_DEV; i++) {
			if (default_off & BIT(i)) {
				tmp.index = i;
				bcm_vc_power_off(&tmp);
			}
		}
	}

	platform_set_drvdata(of_dev, mgr);
	return 0;

err:
	kfree(mgr);
	return ret;
}

static int bcm_vc_power_mgr_remove(struct platform_device *of_dev)
{
	struct bcm_vc_power_mgr *mgr = platform_get_drvdata(of_dev);

	bcm_mbox_put(mgr->mbox);
	kfree(mgr);
	platform_set_drvdata(of_dev, NULL);
	return 0;
}

bool bcm_vc_power_is_user(struct device_node *node)
{
	if (node == NULL)
		return false;

	return of_device_is_compatible(node, "broadcom,bcm2708-power-user");
}

struct bcm_vc_power_dev *bcm_vc_power_get(struct device_node *node,
	const char *pname, const char *pindex)
{
	struct device_node *power_node;
	struct platform_device *pdev;
	struct bcm_vc_power_mgr *mgr;
	struct bcm_vc_power_dev *dev;
	u32 index;
	int ret;

	if (node == NULL)
		return ERR_PTR(-EINVAL);

	if (pname == NULL)
		pname = "broadcom,vc-power";

	if (pindex == NULL)
		pindex = "broadcom,vc-index";

	if (of_property_read_u32(node, pindex, &index))
		return ERR_PTR(-EINVAL);

	if (index > MAX_POWER_DEV)
		return ERR_PTR(-EOVERFLOW);

	power_node = of_parse_phandle(node, pname, 0);
	if (power_node == NULL)
		return ERR_PTR(-ENOENT);

	pdev = of_find_device_by_node(power_node);
	if (pdev == NULL) {
		of_node_put(power_node);
		return ERR_PTR(-ENODEV);
	}

	/* swap our node ref for a device ref */
	get_device(&pdev->dev);
	of_node_put(power_node);

	if (pdev->dev.driver == NULL
			|| pdev->dev.driver->owner != THIS_MODULE) {
		ret = -ENODEV;
		goto put_dev;
	}

	mgr = platform_get_drvdata(pdev);
	if (mgr == NULL || mgr->dev != &pdev->dev) {
		ret = -EINVAL;
		goto put_dev;
	}

	/* check the index is valid */
	if (!(mgr->valid & BIT(index))) {
		ret = -ECHRNG;
		goto put_dev;
	}

	/* create a reference */
	dev = kmalloc(sizeof(*dev), GFP_KERNEL);
	if (dev == NULL) {
		ret = -ENOMEM;
		goto put_dev;
	}

	mutex_lock(&mgr->lock);
	if (mgr->open[index]) {
		ret = -EBUSY;
		goto out_free;
	}
	mgr->open[index] = true;
	mutex_unlock(&mgr->lock);

	dev->mgr = mgr;
	dev->index = index;
	return dev;

out_free:
	kfree(dev);
put_dev:
	put_device(&pdev->dev);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(bcm_vc_power_get);

static void __bcm_vc_power_off(struct bcm_vc_power_dev *dev)
{
	struct bcm_vc_power_mgr *mgr;
	bool state;

	mgr = dev->mgr;
	state = mgr->state & BIT(dev->index);
	if (!state) {
		dev_dbg(mgr->dev, "power off %d\n", dev->index);

		mgr->state &= ~(BIT(dev->index));
		bcm_mbox_write(mgr->mbox, PWR_TO_MBOX(mgr->state));
	}
}

void bcm_vc_power_put(struct bcm_vc_power_dev *dev)
{
	struct bcm_vc_power_mgr *mgr;

	if (dev != NULL && dev->mgr != NULL) {
		mgr = dev->mgr;

		mutex_lock(&mgr->lock);
		__bcm_vc_power_off(dev);
		dev->mgr->open[dev->index] = false;
		mutex_unlock(&mgr->lock);

		put_device(mgr->dev);
	} else  {
		WARN_ON(1);
	}
	kfree(dev);
}
EXPORT_SYMBOL_GPL(bcm_vc_power_put);

int bcm_vc_power_on(struct bcm_vc_power_dev *dev)
{
	struct bcm_vc_power_mgr *mgr;
	bool state;

	if (dev == NULL || dev->mgr == NULL)
		return -EINVAL;
	mgr = dev->mgr;

	mutex_lock(&mgr->lock);
	state = mgr->state & BIT(dev->index);
	if (!state) {
		u32 val;

		dev_dbg(mgr->dev, "power on %d\n", dev->index);

		mgr->state |= BIT(dev->index);
		bcm_mbox_call(mgr->mbox, PWR_TO_MBOX(mgr->state), &val);
		mgr->state = MBOX_TO_PWR(val) & PMASK;
	}
	state = mgr->state & BIT(dev->index);
	mutex_unlock(&mgr->lock);

	dev_dbg(mgr->dev, "power for %d %s\n", dev->index,
		state ? "ok" : "failed");

	return state ? 0 : -EAGAIN;
}
EXPORT_SYMBOL_GPL(bcm_vc_power_on);

int bcm_vc_power_state(struct bcm_vc_power_dev *dev)
{
	struct bcm_vc_power_mgr *mgr;
	bool state;

	if (dev == NULL || dev->mgr == NULL)
		return -EINVAL;
	mgr = dev->mgr;

	mutex_lock(&mgr->lock);
	state = mgr->state & BIT(dev->index);
	mutex_unlock(&mgr->lock);

	return state ? 0 : -ESRCH;
}
EXPORT_SYMBOL_GPL(bcm_vc_power_state);

void bcm_vc_power_off(struct bcm_vc_power_dev *dev)
{
	struct bcm_vc_power_mgr *mgr;

	if (dev == NULL || dev->mgr == NULL)
		return;
	mgr = dev->mgr;

	mutex_lock(&mgr->lock);
	__bcm_vc_power_off(dev);
	mutex_unlock(&mgr->lock);
}
EXPORT_SYMBOL_GPL(bcm_vc_power_off);

static struct of_device_id bcm_vc_power_mgr_dt_match[] __devinitconst = {
	{ .compatible = "broadcom,bcm2708-power-mgr" },
	{}
};
MODULE_DEVICE_TABLE(of, bcm_vc_power_mgr_dt_match);

static struct platform_driver bcm_vc_power_mgr_driver = {
	.probe = bcm_vc_power_mgr_probe,
	.remove = bcm_vc_power_mgr_remove,
	.driver = {
		.name = MODULE_NAME,
		.owner = THIS_MODULE,
		.of_match_table = bcm_vc_power_mgr_dt_match
	}
};

static int __init bcm_vc_power_mgr_init(void)
{
	int ret;
	printk(KERN_INFO MODULE_NAME ": Broadcom VideoCore power manager driver\n");

	ret = platform_driver_register(&bcm_vc_power_mgr_driver);
	if (ret)
		printk(KERN_ERR MODULE_NAME ": registration failed (%d)\n", ret);

	return ret;
}

static void __exit bcm_vc_power_mgr_exit(void)
{
	platform_driver_unregister(&bcm_vc_power_mgr_driver);
}

arch_initcall(bcm_vc_power_mgr_init);
module_exit(bcm_vc_power_mgr_exit);

MODULE_AUTHOR("Phil Elwell, Simon Arlott");
MODULE_DESCRIPTION("Interface to Broadcom VideoCore power management");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:bcm-vc-power");
