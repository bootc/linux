/*
 * Copyright (C) 2010 Broadcom
 * Copyright 2012 Simon Arlott
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This device provides a mechanism for using the doorbells shared
 * between the ARM and the VideoCore processor.
 */

#include <linux/device.h>
#include <linux/err.h>
#include <linux/gpio.h>
#include <linux/io.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/interrupt.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#define MODULE_NAME "bcm-bell"

#define BCM_NUM_BELLS		4

#define REG_DEBUG_OWNER_OFFSET	0
#define REG_DEBUG_VALUE_OFFSET	8

struct bcm_bell;

struct bcm_bell_irq {
	struct bcm_bell *bell;
	int irq;
	int id;

	struct spinlock lock;
	bool enabled;
};

struct bcm_bell {
	struct device *dev;
	void __iomem *base;
	void __iomem *debug;

	struct irq_domain *irq_domain;
	struct gpio_chip gpio_chip;
	struct bcm_bell_irq irq[BCM_NUM_BELLS];

	struct mutex lock;
	unsigned long used_map;
};

static struct lock_class_key bell_lock_class;

static irqreturn_t bcm_bell_irq_handler(int irq, void *dev_id)
{
	struct bcm_bell_irq *bell_irq = dev_id;
	struct bcm_bell *bell = bell_irq->bell;
	int status = readl(bell->base + bell_irq->id * 4);
	bool enabled;

	/* reading the status also clears it */
	if (status) {
		spin_lock(&bell_irq->lock);
		enabled = bell_irq->enabled;
		spin_unlock(&bell_irq->lock);

		if (enabled)
			generic_handle_irq(irq_linear_revmap(
					bell->irq_domain, bell_irq->id));
		return IRQ_HANDLED;
	} else {
		return IRQ_NONE;
	}
}

static int bcm_bell_request(struct gpio_chip *chip, unsigned offset)
{
	struct bcm_bell *bell = dev_get_drvdata(chip->dev);
	int ret;

	mutex_lock(&bell->lock);
	ret = test_bit(offset, &bell->used_map) ? -EBUSY : 0;
	set_bit(offset, &bell->used_map);
	mutex_unlock(&bell->lock);

	return ret;
}

static void bcm_bell_free(struct gpio_chip *chip, unsigned offset)
{
	struct bcm_bell *bell = dev_get_drvdata(chip->dev);

	mutex_lock(&bell->lock);
	clear_bit(offset, &bell->used_map);
	mutex_unlock(&bell->lock);
}

static int bcm_bell_direction_input(struct gpio_chip *chip, unsigned offset)
{
	return 0;
}

static int bcm_bell_get(struct gpio_chip *chip, unsigned offset)
{
	struct bcm_bell *bell = dev_get_drvdata(chip->dev);
	u32 value = readl(bell->debug) >> REG_DEBUG_VALUE_OFFSET;

	return (value & BIT(offset)) ? 1 : 0;
}

static int bcm_bell_direction_output(struct gpio_chip *chip,
		unsigned offset, int value)
{
	return 0;
}

static void bcm_bell_set(struct gpio_chip *chip, unsigned offset, int value)
{
	struct bcm_bell *bell = dev_get_drvdata(chip->dev);

	/*
	 * We can't safely clear a doorbell as there's only one debug register
	 * for all doorbells so we could accidentally clear our own incoming
	 * ring before the interrupt handler reads it if we read/modify/write
	 */
	if (value)
		writel(0, bell->base + offset * 4);
}

static int bcm_bell_to_irq(struct gpio_chip *chip, unsigned offset)
{
	struct bcm_bell *bell = dev_get_drvdata(chip->dev);

	return irq_linear_revmap(bell->irq_domain, offset);
}

static struct gpio_chip bcm_bell_gpio_chip __devinitconst = {
	.label = MODULE_NAME,
	.owner = THIS_MODULE,
	.request = bcm_bell_request,
	.free = bcm_bell_free,
	.direction_input = bcm_bell_direction_input,
	.get = bcm_bell_get,
	.direction_output = bcm_bell_direction_output,
	.set = bcm_bell_set,
	.to_irq = bcm_bell_to_irq,
	.base = 96,
	.ngpio = BCM_NUM_BELLS,
	.can_sleep = 0,
};

static void bcm_bell_irq_enable(struct irq_data *data)
{
	struct bcm_bell *bell = irq_data_get_irq_chip_data(data);
	unsigned offset = irqd_to_hwirq(data);
	unsigned long flags;

	spin_lock_irqsave(&bell->irq[offset].lock, flags);
	bell->irq[offset].enabled = true;
	spin_unlock_irqrestore(&bell->irq[offset].lock, flags);
}

static void bcm_bell_irq_disable(struct irq_data *data)
{
	struct bcm_bell *bell = irq_data_get_irq_chip_data(data);
	unsigned offset = irqd_to_hwirq(data);
	unsigned long flags;

	spin_lock_irqsave(&bell->irq[offset].lock, flags);
	bell->irq[offset].enabled = false;
	spin_unlock_irqrestore(&bell->irq[offset].lock, flags);
}

static struct irq_chip bcm_bell_irq_chip = {
	.name = "BELL-rising",
	.irq_enable = bcm_bell_irq_enable,
	.irq_disable = bcm_bell_irq_disable,
};

static int __devinit bcm_bell_probe(struct platform_device *pdev)
{
	struct device_node *node = pdev->dev.of_node;
	struct bcm_bell *bell = devm_kzalloc(&pdev->dev,
		sizeof(*bell), GFP_KERNEL);
	struct resource res[2];
	int ret, i;

	if (bell == NULL)
		return -ENOMEM;

	bell->dev = &pdev->dev;
	mutex_init(&bell->lock);

	if (of_address_to_resource(node, 0, &res[0]))
		return -EINVAL;

	if (resource_size(&res[0]) < sizeof(u32) * BCM_NUM_BELLS) {
		dev_err(bell->dev, "resource 0 too small (%#x)\n",
			resource_size(&res[0]));
		return -EINVAL;
	}

	if (of_address_to_resource(node, 1, &res[1]))
		return -EINVAL;

	if (resource_size(&res[1]) < sizeof(u32)) {
		dev_err(bell->dev, "resource 1 too small (%#x)\n",
			resource_size(&res[1]));
		return -EINVAL;
	}

	bell->base = devm_request_and_ioremap(bell->dev, &res[0]);
	if (!bell->base) {
		dev_err(bell->dev, "error mapping io at %#lx\n",
			(unsigned long)res[0].start);
		return -EIO;
	}

	bell->debug = devm_request_and_ioremap(bell->dev, &res[1]);
	if (!bell->debug) {
		dev_err(bell->dev, "error mapping io at %#lx\n",
			(unsigned long)res[1].start);
		return -EIO;
	}

	for (i = 0; i < BCM_NUM_BELLS; i++) {
		int len;
		char *name;

		bell->irq[i].irq = irq_of_parse_and_map(node, i);
		if (!bell->irq[i].irq)
			continue;

		bell->irq[i].bell = bell;
		bell->irq[i].id = i;

		len = strlen(dev_name(bell->dev)) + 16;
		name = devm_kzalloc(bell->dev, len, GFP_KERNEL);
		if (!name)
			continue;
		snprintf(name, len, "%s:bell%d", dev_name(bell->dev), i);

		ret = devm_request_irq(bell->dev, bell->irq[i].irq,
			bcm_bell_irq_handler, 0, name, &bell->irq[i]);
		if (ret) {
			dev_err(bell->dev, "unable to request irq %d",
				bell->irq[i].irq);
			return ret;
		}
	}

	bell->irq_domain = irq_domain_add_linear(node, BCM_NUM_BELLS,
			&irq_domain_simple_ops, NULL);
	if (!bell->irq_domain) {
		dev_err(bell->dev, "could not create IRQ domain\n");
		return -ENOMEM;
	}

	for (i = 0; i < BCM_NUM_BELLS; i++) {
		int irq;

		spin_lock_init(&bell->irq[i].lock);
		if (!bell->irq[i].irq)
			continue;

		irq = irq_create_mapping(bell->irq_domain, i);
		irq_set_lockdep_class(irq, &bell_lock_class);
		irq_set_chip_and_handler(irq, &bcm_bell_irq_chip,
				handle_simple_irq);
		irq_set_chip_data(irq, bell);
		set_irq_flags(irq, IRQF_VALID);
	}

	bell->gpio_chip = bcm_bell_gpio_chip;
	bell->gpio_chip.dev = bell->dev;
	bell->gpio_chip.of_node = node;

	ret = gpiochip_add(&bell->gpio_chip);
	if (ret) {
		dev_err(bell->dev, "could not add GPIO chip\n");
		return ret;
	}

	for (i = 0; i < BCM_NUM_BELLS; i++) {
		if (bell->irq[i].irq) {
			dev_info(bell->dev, "doorbell at MMIO %#lx (irq = %d)\n",
				(unsigned long)res[0].start + i * 4,
				bell->irq[i].irq);
		} else {
			dev_info(bell->dev, "doorbell at MMIO %#lx\n",
				(unsigned long)res[0].start + i * 4);
		}
	}

	platform_set_drvdata(pdev, bell);
	return 0;
}

static int bcm_bell_remove(struct platform_device *pdev)
{
	struct bcm_bell *bell = platform_get_drvdata(pdev);
	int ret;

	ret = gpiochip_remove(&bell->gpio_chip);
	if (ret)
		return ret;

	platform_set_drvdata(pdev, NULL);
	return 0;
}

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
	printk(KERN_INFO MODULE_NAME ": Broadcom VideoCore Doorbell driver\n");

	return platform_driver_register(&bcm_bell_driver);
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
