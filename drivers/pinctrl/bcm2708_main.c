/*
 * Copyright 2012 Simon Arlott
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * publishhed by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <linux/err.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/pinctrl/pinctrl.h>
#include <linux/pinctrl/pinmux.h>
#include <linux/pinctrl/pinconf.h>
#include <linux/pinctrl/machine.h>

#include "bcm2708.h"

#define MODULE_NAME "pinctrl-bcm2708"

static int __devinit bcm2708_pinctrl_register(struct bcm2708_pinctrl *pc)
{
	struct pinctrl_desc *desc = &pc->desc;
	int ret;

	desc->name = dev_name(pc->dev);
	desc->pins = pc->pindesc;
	desc->npins = pc->nr_pins;
	desc->pctlops = &pc->pctlops;
	desc->pmxops = &pc->pmxops;
	/* TODO: pinconf support */
	/* desc->confops = &pc->confops; */
	desc->owner = THIS_MODULE;

	pc->pctlops.get_groups_count = bcm2708_pinctrl_get_groups_count;
	pc->pctlops.get_group_name = bcm2708_pinctrl_get_group_name;
	pc->pctlops.get_group_pins = bcm2708_pinctrl_get_group_pins;

	pc->pmxops.request = bcm2708_pinmux_request;
	pc->pmxops.free = bcm2708_pinmux_free;
	pc->pmxops.get_functions_count = bcm2708_pinmux_get_functions_count;
	pc->pmxops.get_function_name = bcm2708_pinmux_get_function_name;
	pc->pmxops.get_function_groups = bcm2708_pinmux_get_function_groups;
	pc->pmxops.enable = bcm2708_pinmux_enable;
	pc->pmxops.disable = bcm2708_pinmux_disable;
	pc->pmxops.gpio_request_enable = bcm2708_pinmux_gpio_request_enable;
	pc->pmxops.gpio_disable_free = bcm2708_pinmux_gpio_disable_free;
	pc->pmxops.gpio_set_direction = bcm2708_pinmux_gpio_set_direction;

	pc->gpio_range.name = dev_name(pc->dev);
	pc->gpio_range.gc = NULL;

	pc->pctl = pinctrl_register(desc, pc->dev, pc);
	if (IS_ERR(pc->pctl))
		return PTR_ERR(pc->pctl);

	/* mappings can't be unregistered, don't fail after this */
	ret = pinctrl_register_mappings(pc->pinmap, pc->nr_pinmaps);
	if (ret)
		goto err;

	pinctrl_add_gpio_range(pc->pctl, &pc->gpio_range);
	return 0;

err:
	pinctrl_unregister(pc->pctl);
	return ret;
}

static void __devexit bcm2708_pinctrl_unregister(struct bcm2708_pinctrl *pc)
{
	pinctrl_remove_gpio_range(pc->pctl, &pc->gpio_range);
	/* can't unregister mappings! */
	WARN_ON(pc->nr_pinmaps > 0);
	pinctrl_unregister(pc->pctl);
}

static int __devinit bcm2708_pinctrl_probe(struct platform_device *pdev)
{
	struct bcm2708_pinctrl *pc = bcm2708_pinctrl_of_init(pdev);
	int ret;

	if (IS_ERR(pc))
		return PTR_ERR(pc);

	ret = bcm2708_pinctrl_sysfs_register(pc);
	if (ret)
		goto err_free;

	ret = bcm2708_pinctrl_register(pc);
	if (ret)
		goto err_sysfs;

	mutex_lock(&pc->lock);
	pc->active = true;
	mutex_unlock(&pc->lock);

	dev_info(pc->dev, "%d pins at MMIO %#lx\n", pc->nr_pins,
		(unsigned long)pc->res.start);

	platform_set_drvdata(pdev, pc);
	return 0;

err_sysfs:
	bcm2708_pinctrl_sysfs_unregister(pc);
err_free:
	bcm2708_pinctrl_of_free(pc);
	return ret;
}

static int __devexit bcm2708_pinctrl_remove(struct platform_device *pdev)
{
	struct bcm2708_pinctrl *pc = platform_get_drvdata(pdev);

	/* can't unregister mappings! */
	if (pc->nr_pinmaps > 0)
		return -EBUSY;

	/* make sure no sysfs activity can occur */
	mutex_lock(&pc->lock);
	pc->active = false;
	mutex_unlock(&pc->lock);

	bcm2708_pinctrl_unregister(pc);
	bcm2708_pinctrl_sysfs_unregister(pc);
	bcm2708_pinctrl_of_free(pc);
	platform_set_drvdata(pdev, NULL);
	return 0;
}

static struct of_device_id bcm2708_pinctrl_match[] __devinitconst = {
	{ .compatible = "broadcom,bcm2708-pinctrl" },
	{}
};
MODULE_DEVICE_TABLE(of, bcm2708_pinctrl_match);

static struct platform_driver bcm2708_pinctrl_driver = {
	.probe = bcm2708_pinctrl_probe,
	.remove = bcm2708_pinctrl_remove,
	.driver = {
		.name = MODULE_NAME,
		.owner = THIS_MODULE,
		.of_match_table = bcm2708_pinctrl_match
	}
};

static int __init bcm2708_pinctrl_init(void)
{
	return platform_driver_register(&bcm2708_pinctrl_driver);
}

static void __exit bcm2708_pinctrl_exit(void)
{
	platform_driver_unregister(&bcm2708_pinctrl_driver);
}
arch_initcall(bcm2708_pinctrl_init);
module_exit(bcm2708_pinctrl_exit);

MODULE_AUTHOR("Simon Arlott");
MODULE_DESCRIPTION("BCM2708 Pin control driver");
MODULE_LICENSE("GPL");
