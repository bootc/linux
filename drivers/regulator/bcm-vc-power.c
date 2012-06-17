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

#include <linux/bcm-mbox.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/regulator/driver.h>
#include <linux/regulator/machine.h>
#include <linux/regulator/of_regulator.h>

#define MODULE_NAME "bcm-vc-power"

/* 27 bits available in mbox (0-26) */
#define MAX_POWER_DEV 26
#define PMASK  0x07ffffff
#define PQUERY 0x08000000

#define PWR_TO_MBOX(x) ((x) << 4)
#define MBOX_TO_PWR(x) ((x) >> 4)

struct bcm_vc_power_mgr {
	struct device *dev;
	int fixed_uV;

	/* used to lock mbox, state */
	struct mutex lock;
	struct bcm_mbox_chan *mbox;
	u32 state;

	struct regulator_dev *rdev;
};

struct bcm_vc_power_dev {
	struct device *dev;
	int fixed_uV;

	struct bcm_vc_power_mgr *mgr;
	int index;
	struct regulator_dev *rdev;
};

static int bcm_vc_power_enable(struct regulator_dev *rdev)
{
	struct bcm_vc_power_dev *pdev = rdev_get_drvdata(rdev);
	struct bcm_vc_power_mgr *mgr = pdev->mgr;
	bool state;

	mutex_lock(&mgr->lock);
	state = mgr->state & BIT(pdev->index);
	if (!state) {
		u32 val;

		dev_dbg(pdev->dev, "power on\n");

		mgr->state |= BIT(pdev->index);
		bcm_mbox_call(mgr->mbox, PWR_TO_MBOX(mgr->state), &val);
		mgr->state = MBOX_TO_PWR(val) & PMASK;
	}
	state = mgr->state & BIT(pdev->index);
	mutex_unlock(&mgr->lock);

	dev_dbg(pdev->dev, "power %s\n", state ? "ok" : "failed");

	return state ? 0 : -EAGAIN;
}

static int bcm_vc_power_disable(struct regulator_dev *rdev)
{
	struct bcm_vc_power_dev *pdev = rdev_get_drvdata(rdev);
	struct bcm_vc_power_mgr *mgr = pdev->mgr;
	bool state;

	mutex_lock(&mgr->lock);
	state = mgr->state & BIT(pdev->index);
	if (state) {
		dev_dbg(pdev->dev, "power off\n");

		mgr->state &= ~(BIT(pdev->index));
		bcm_mbox_write(mgr->mbox, PWR_TO_MBOX(mgr->state));
	}
	mutex_unlock(&mgr->lock);

	return 0;
}

static int bcm_vc_power_is_enabled(struct regulator_dev *rdev)
{
	struct bcm_vc_power_dev *pdev = rdev_get_drvdata(rdev);
	struct bcm_vc_power_mgr *mgr = pdev->mgr;
	bool state;

	mutex_lock(&mgr->lock);
	state = mgr->state & BIT(pdev->index);
	mutex_unlock(&mgr->lock);

	return state;
}

static int bcm_vc_power_enable_time(struct regulator_dev *rdev)
{
	return 10000; /* 10ms */
}

static int bcm_vc_power_list_mgr_voltage(struct regulator_dev *rdev,
	unsigned selector)
{
	struct bcm_vc_power_mgr *mgr = rdev_get_drvdata(rdev);

	return selector == 0 ? mgr->fixed_uV : 0;
}

static int bcm_vc_power_get_mgr_voltage(struct regulator_dev *rdev)
{
	struct bcm_vc_power_mgr *mgr = rdev_get_drvdata(rdev);

	return mgr->fixed_uV;
}

static int bcm_vc_power_list_dev_voltage(struct regulator_dev *rdev,
	unsigned selector)
{
	struct bcm_vc_power_dev *pdev = rdev_get_drvdata(rdev);

	return selector == 0 ? pdev->fixed_uV : 0;
}

static int bcm_vc_power_get_dev_voltage(struct regulator_dev *rdev)
{
	struct bcm_vc_power_dev *pdev = rdev_get_drvdata(rdev);

	return pdev->fixed_uV;
}

static struct regulator_ops mgr_ops = {
	.list_voltage = bcm_vc_power_list_mgr_voltage,
	.get_voltage = bcm_vc_power_get_mgr_voltage
};

static const struct regulator_desc mgr_desc = {
	.name = MODULE_NAME,
	.id = -1,
	.type = REGULATOR_VOLTAGE,
	.owner = THIS_MODULE,
	.ops = &mgr_ops,
	.n_voltages = 1
};

static struct regulator_ops dev_ops = {
	.enable = bcm_vc_power_enable,
	.disable = bcm_vc_power_disable,
	.is_enabled = bcm_vc_power_is_enabled,
	.enable_time = bcm_vc_power_enable_time,

	.list_voltage = bcm_vc_power_list_dev_voltage,
	.get_voltage = bcm_vc_power_get_dev_voltage
};

static const struct regulator_desc dev_desc = {
	.name = MODULE_NAME,
	.id = -1,
	.type = REGULATOR_VOLTAGE,
	.owner = THIS_MODULE,
	.ops = &dev_ops,
	.n_voltages = 1
};

static int __devinit bcm_vc_power_mgr_probe(struct platform_device *of_dev)
{
	struct device_node *node = of_dev->dev.of_node;
	struct bcm_vc_power_mgr *mgr = devm_kzalloc(&of_dev->dev,
		sizeof(*mgr), GFP_KERNEL);
	struct regulator_init_data *init_data;
	struct regulator_config config = {
		.dev = &of_dev->dev,
		.of_node = node,
		.driver_data = mgr
	};
	char *name;
	int ret;

	if (mgr == NULL)
		return -ENOMEM;

	mgr->dev = &of_dev->dev;
	mutex_init(&mgr->lock);
	mgr->mbox = bcm_mbox_get(node, "broadcom,vc-mailbox", "broadcom,vc-channel");

	if (IS_ERR(mgr->mbox)) {
		dev_err(mgr->dev, "unable to find mailbox channel (%ld)\n",
			PTR_ERR(mgr->mbox));
		return -ENOENT;
	}

	name = bcm_mbox_name(mgr->mbox);
	dev_info(mgr->dev, "attached to mailbox %s\n", name);
	kfree(name);

	/* power everything off */
	bcm_mbox_clear(mgr->mbox);
	ret = bcm_mbox_write(mgr->mbox, PWR_TO_MBOX(0));
	if (ret)
		goto err;

	/* find out what is powered on */
	bcm_mbox_clear(mgr->mbox);
	ret = bcm_mbox_call_interruptible(mgr->mbox, PQUERY, &mgr->state);
	if (ret)
		goto err;
	mgr->state = MBOX_TO_PWR(mgr->state) & PMASK;

	dev_dbg(mgr->dev, "current = %08x\n", mgr->state);

	init_data = of_get_regulator_init_data(mgr->dev, node);
	init_data->constraints.apply_uV = false;
	WARN_ON(init_data->constraints.min_uV != init_data->constraints.max_uV);
	mgr->fixed_uV = init_data->constraints.max_uV;
	config.init_data = init_data;

	mgr->rdev = regulator_register(&mgr_desc, &config);
	if (IS_ERR(mgr->rdev)) {
		ret = PTR_ERR(mgr->rdev);
		dev_warn(mgr->dev, "failed to register regulator (%d)\n", ret);
		goto err;
	}

	platform_set_drvdata(of_dev, mgr);
	return 0;

err:
	bcm_mbox_put(mgr->mbox);
	return ret;
}

static int __devexit bcm_vc_power_mgr_remove(struct platform_device *of_dev)
{
	struct bcm_vc_power_mgr *mgr = platform_get_drvdata(of_dev);

	regulator_unregister(mgr->rdev);
	bcm_mbox_put(mgr->mbox);
	platform_set_drvdata(of_dev, NULL);
	return 0;
}

static int __devinit bcm_vc_power_dev_probe(struct platform_device *of_dev)
{
	struct device_node *node = of_dev->dev.of_node;
	struct bcm_vc_power_dev *pdev = devm_kzalloc(&of_dev->dev,
			sizeof(*pdev), GFP_KERNEL);
	struct platform_device *mgr;
	struct regulator_init_data *init_data;
	struct regulator_config config = {
		.dev = &of_dev->dev,
		.of_node = node,
		.driver_data = pdev
	};
	const __be32 *index;

	if (pdev == NULL)
		return -ENOMEM;

	index = of_get_property(node, "reg", NULL);
	if (index == NULL)
		return -EIO;

	if (of_dev->dev.parent == &platform_bus)
		return -ENODEV;

	mgr = to_platform_device(of_dev->dev.parent);
	if (mgr == NULL)
		return -ENODEV;

	pdev->dev = &of_dev->dev;
	pdev->mgr = platform_get_drvdata(mgr);
	if (pdev->mgr == NULL)
		return -EPROBE_DEFER;

	pdev->index = be32_to_cpu(*index);
	if (pdev->index < 0 || pdev->index > MAX_POWER_DEV)
		return -EINVAL;

	init_data = of_get_regulator_init_data(pdev->dev, node);
	init_data->constraints.apply_uV = false;
	WARN_ON(init_data->constraints.min_uV != init_data->constraints.max_uV);
	pdev->fixed_uV = init_data->constraints.max_uV;
	config.init_data = init_data;

	pdev->rdev = regulator_register(&dev_desc, &config);
	if (IS_ERR(pdev->rdev)) {
		int ret = PTR_ERR(pdev->rdev);
		dev_warn(pdev->dev, "failed to register regulator (%d)\n", ret);
		return ret;
	}

	platform_set_drvdata(of_dev, mgr);
	return 0;
}

static int __devexit bcm_vc_power_dev_remove(struct platform_device *of_dev)
{
	struct bcm_vc_power_dev *pdev = platform_get_drvdata(of_dev);

	regulator_unregister(pdev->rdev);
	platform_set_drvdata(of_dev, NULL);
	return 0;
}

static struct of_device_id bcm_vc_power_mgr_dt_match[] __devinitconst = {
	{ .compatible = "broadcom,bcm2708-power-mgr" },
	{}
};
MODULE_DEVICE_TABLE(of, bcm_vc_power_mgr_dt_match);

static struct platform_driver bcm_vc_power_mgr_driver = {
	.probe = bcm_vc_power_mgr_probe,
	.remove = __devexit_p(bcm_vc_power_mgr_remove),
	.driver = {
		.name = MODULE_NAME "-mgr",
		.owner = THIS_MODULE,
		.of_match_table = bcm_vc_power_mgr_dt_match
	}
};

static struct of_device_id bcm_vc_power_dev_dt_match[] __devinitconst = {
	{ .compatible = "broadcom,bcm2708-power-dev" },
	{}
};
MODULE_DEVICE_TABLE(of, bcm_vc_power_dev_dt_match);

static struct platform_driver bcm_vc_power_dev_driver = {
	.probe = bcm_vc_power_dev_probe,
	.remove = __devexit_p(bcm_vc_power_dev_remove),
	.driver = {
		.name = MODULE_NAME "-dev",
		.owner = THIS_MODULE,
		.of_match_table = bcm_vc_power_dev_dt_match
	}
};

static int __init bcm_vc_power_mgr_init(void)
{
	int ret;
	printk(KERN_INFO MODULE_NAME ": Broadcom VideoCore power manager driver\n");

	ret = platform_driver_register(&bcm_vc_power_mgr_driver);
	if (ret)
		return ret;

	ret = platform_driver_register(&bcm_vc_power_dev_driver);
	if (ret)
		platform_driver_unregister(&bcm_vc_power_mgr_driver);

	return ret;
}

static void __exit bcm_vc_power_mgr_exit(void)
{
	platform_driver_unregister(&bcm_vc_power_dev_driver);
	platform_driver_unregister(&bcm_vc_power_mgr_driver);
}

subsys_initcall(bcm_vc_power_mgr_init);
module_exit(bcm_vc_power_mgr_exit);

MODULE_AUTHOR("Phil Elwell, Simon Arlott");
MODULE_DESCRIPTION("Interface to Broadcom VideoCore power management");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:bcm-vc-power");
