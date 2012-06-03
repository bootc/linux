/*
 * Driver for Broadcom BCM2708 GPIO unit (pinctl + GPIO)
 *
 * Copyright (C) 2012 Chris Boot, Simon Arlott
 *
 * This driver is inspired by:
 * XXX
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

#include <linux/bitmap.h>
#include <linux/bug.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/gpio.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/pinctrl/pinctrl.h>
#include <linux/pinctrl/pinmux.h>
#include <linux/pinctrl/pinconf.h>
#include <linux/pinctrl/machine.h>
#include <linux/platform_device.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/types.h>

#define MODULE_NAME "pinctrl-bcm2708"
#define BCM2708_NUM_GPIOS 54

#define BCM2708_PIN_BITMAP_SZ \
	DIV_ROUND_UP(BCM2708_NUM_GPIOS, sizeof(unsigned long) * 8)

struct bcm2708_pinctrl {
	struct device *dev;
	void __iomem *base;
	unsigned long readonly_map[BCM2708_PIN_BITMAP_SZ];

	struct pinctrl_dev *pctl_dev;
};

/* pins are just named GPIO0..GPIO53 */
#define BCM2708_GPIO_PIN(a) PINCTRL_PIN(a, "GPIO" #a)
struct pinctrl_pin_desc bcm2708_gpio_pins[] = {
	BCM2708_GPIO_PIN(0),
	BCM2708_GPIO_PIN(1),
	BCM2708_GPIO_PIN(2),
	BCM2708_GPIO_PIN(3),
	BCM2708_GPIO_PIN(4),
	BCM2708_GPIO_PIN(5),
	BCM2708_GPIO_PIN(6),
	BCM2708_GPIO_PIN(7),
	BCM2708_GPIO_PIN(8),
	BCM2708_GPIO_PIN(9),
	BCM2708_GPIO_PIN(10),
	BCM2708_GPIO_PIN(11),
	BCM2708_GPIO_PIN(12),
	BCM2708_GPIO_PIN(13),
	BCM2708_GPIO_PIN(14),
	BCM2708_GPIO_PIN(15),
	BCM2708_GPIO_PIN(16),
	BCM2708_GPIO_PIN(17),
	BCM2708_GPIO_PIN(18),
	BCM2708_GPIO_PIN(19),
	BCM2708_GPIO_PIN(20),
	BCM2708_GPIO_PIN(21),
	BCM2708_GPIO_PIN(22),
	BCM2708_GPIO_PIN(23),
	BCM2708_GPIO_PIN(24),
	BCM2708_GPIO_PIN(25),
	BCM2708_GPIO_PIN(26),
	BCM2708_GPIO_PIN(27),
	BCM2708_GPIO_PIN(28),
	BCM2708_GPIO_PIN(29),
	BCM2708_GPIO_PIN(30),
	BCM2708_GPIO_PIN(31),
	BCM2708_GPIO_PIN(32),
	BCM2708_GPIO_PIN(33),
	BCM2708_GPIO_PIN(34),
	BCM2708_GPIO_PIN(35),
	BCM2708_GPIO_PIN(36),
	BCM2708_GPIO_PIN(37),
	BCM2708_GPIO_PIN(38),
	BCM2708_GPIO_PIN(39),
	BCM2708_GPIO_PIN(40),
	BCM2708_GPIO_PIN(41),
	BCM2708_GPIO_PIN(42),
	BCM2708_GPIO_PIN(43),
	BCM2708_GPIO_PIN(44),
	BCM2708_GPIO_PIN(45),
	BCM2708_GPIO_PIN(46),
	BCM2708_GPIO_PIN(47),
	BCM2708_GPIO_PIN(48),
	BCM2708_GPIO_PIN(49),
	BCM2708_GPIO_PIN(50),
	BCM2708_GPIO_PIN(51),
	BCM2708_GPIO_PIN(52),
	BCM2708_GPIO_PIN(53),
};

/* one pin per group */
static const char *bcm2708_gpio_groups[] = {
	"GPIO0",
	"GPIO1",
	"GPIO2",
	"GPIO3",
	"GPIO4",
	"GPIO5",
	"GPIO6",
	"GPIO7",
	"GPIO8",
	"GPIO9",
	"GPIO10",
	"GPIO11",
	"GPIO12",
	"GPIO13",
	"GPIO14",
	"GPIO15",
	"GPIO16",
	"GPIO17",
	"GPIO18",
	"GPIO19",
	"GPIO20",
	"GPIO21",
	"GPIO22",
	"GPIO23",
	"GPIO24",
	"GPIO25",
	"GPIO26",
	"GPIO27",
	"GPIO28",
	"GPIO29",
	"GPIO30",
	"GPIO31",
	"GPIO32",
	"GPIO33",
	"GPIO34",
	"GPIO35",
	"GPIO36",
	"GPIO37",
	"GPIO38",
	"GPIO39",
	"GPIO40",
	"GPIO41",
	"GPIO42",
	"GPIO43",
	"GPIO44",
	"GPIO45",
	"GPIO46",
	"GPIO47",
	"GPIO48",
	"GPIO49",
	"GPIO50",
	"GPIO51",
	"GPIO52",
	"GPIO53",
};

enum bcm2708_fsel {
	BCM2708_FSEL_GPIO_IN = 0,
	BCM2708_FSEL_GPIO_OUT = 1,
	BCM2708_FSEL_ALT0 = 4,
	BCM2708_FSEL_ALT1 = 5,
	BCM2708_FSEL_ALT2 = 6,
	BCM2708_FSEL_ALT3 = 7,
	BCM2708_FSEL_ALT4 = 3,
	BCM2708_FSEL_ALT5 = 2,
	BCM2708_FSEL_COUNT = 8,
	BCM2708_FSEL_MASK = 0x7,
};

static const char *bcm2708_functions[BCM2708_FSEL_COUNT] = {
	[BCM2708_FSEL_GPIO_IN] = "GPIO_IN",
	[BCM2708_FSEL_GPIO_OUT] = "GPIO_OUT",
	[BCM2708_FSEL_ALT0] = "ALT0",
	[BCM2708_FSEL_ALT1] = "ALT1",
	[BCM2708_FSEL_ALT2] = "ALT2",
	[BCM2708_FSEL_ALT3] = "ALT3",
	[BCM2708_FSEL_ALT4] = "ALT4",
	[BCM2708_FSEL_ALT5] = "ALT5",
};

#define FSEL_REG(p)	(((p) / 10) * 4)
#define FSEL_SHIFT(p)	(((p) % 10) * 3)

static inline enum bcm2708_fsel bcm2708_pinctrl_fsel_get(
		struct bcm2708_pinctrl *pc, unsigned pin)
{
	void __iomem *reg = pc->base + FSEL_REG(pin);
	u32 val = readl(reg);
	enum bcm2708_fsel status = (val >> FSEL_SHIFT(pin)) & BCM2708_FSEL_MASK;

	dev_dbg(pc->dev, "get %08x (%u => %s)\n", val, pin,
			bcm2708_functions[status]);

	return status;
}

static inline void bcm2708_pinctrl_fsel_set(
		struct bcm2708_pinctrl *pc, unsigned pin,
		enum bcm2708_fsel fsel)
{
	void __iomem *reg = pc->base + FSEL_REG(pin);
	u32 val = readl(reg);
	enum bcm2708_fsel cur = (val >> FSEL_SHIFT(pin)) & BCM2708_FSEL_MASK;

	dev_dbg(pc->dev, "read %08x (%u => %s)\n", val, pin,
			bcm2708_functions[cur]);

	if (cur == fsel)
		return;

	if (cur != BCM2708_FSEL_GPIO_IN) {
		/* always transition through GPIO_IN */
		val &= ~(BCM2708_FSEL_MASK << FSEL_SHIFT(pin));
		val |= BCM2708_FSEL_GPIO_IN << FSEL_SHIFT(pin);

		dev_dbg(pc->dev, "write %08x (%u <= %s)\n", val, pin,
				bcm2708_functions[BCM2708_FSEL_GPIO_IN]);
		writel(val, reg);
	} else if (fsel == BCM2708_FSEL_GPIO_IN) {
		return;
	}

	val &= ~(BCM2708_FSEL_MASK << FSEL_SHIFT(pin));
	val |= fsel << FSEL_SHIFT(pin);

	dev_dbg(pc->dev, "write %08x (%u <= %s)\n", val, pin,
			bcm2708_functions[fsel]);
	writel(val, reg);
}

static inline bool bcm2708_warn_readonly(struct bcm2708_pinctrl *pc, int pin,
		enum bcm2708_fsel fsel)
{
	enum bcm2708_fsel cur;

	/* we only care about pins marked read-only */
	if (!test_bit(pin, pc->readonly_map))
		return false;

	cur = bcm2708_pinctrl_fsel_get(pc, pin);

	/* don't care if the requested state is the same */
	if (fsel == cur)
		return false;

	/* shout loudly if asked to change a read-only pin */
	dev_err(pc->dev, "pin %d is a read-only pin!\n", pin);
	WARN_ON(fsel != cur);

	return true;
}

static int bcm2708_pctl_get_groups_count(struct pinctrl_dev *pctldev)
{
	/* make sure all pins are defined */
	BUILD_BUG_ON(ARRAY_SIZE(bcm2708_gpio_groups) != BCM2708_NUM_GPIOS);

	/* one group per pin */
	return ARRAY_SIZE(bcm2708_gpio_groups);
}

static const char *bcm2708_pctl_get_group_name(struct pinctrl_dev *pctldev,
		unsigned selector)
{
	if (selector >= ARRAY_SIZE(bcm2708_gpio_groups))
		return ERR_PTR(-EINVAL);

	/* use the pin name as the group name */
	return bcm2708_gpio_groups[selector];
}

static int bcm2708_pctl_get_group_pins(struct pinctrl_dev *pctldev,
		unsigned selector,
		const unsigned **pins,
		unsigned *num_pins)
{
	/* make sure we have one group per pin */
	BUILD_BUG_ON(ARRAY_SIZE(bcm2708_gpio_pins) != BCM2708_NUM_GPIOS);

	if (selector >= ARRAY_SIZE(bcm2708_gpio_groups))
		return -EINVAL;

	*pins = &bcm2708_gpio_pins[selector].number;
	*num_pins = 1;

	return 0;
}

static void bcm2708_pctl_pin_dbg_show(struct pinctrl_dev *pctldev,
		struct seq_file *s,
		unsigned offset)
{
	struct bcm2708_pinctrl *pc = pinctrl_dev_get_drvdata(pctldev);
	enum bcm2708_fsel fsel = bcm2708_pinctrl_fsel_get(pc, offset);

	seq_printf(s, "function %s (%d) ", bcm2708_functions[fsel], fsel);

	if (test_bit(offset, pc->readonly_map))
		seq_puts(s, "READ-ONLY");
}

static void bcm2708_pctl_dt_free_map(struct pinctrl_dev *pctldev,
		struct pinctrl_map *maps, unsigned num_maps)
{
	struct bcm2708_pinctrl *pc = pinctrl_dev_get_drvdata(pctldev);
	int i;

	for (i = 0; i < num_maps; i++) {
		if (maps[i].type == PIN_MAP_TYPE_CONFIGS_GROUP)
			devm_kfree(pc->dev, maps[i].data.configs.configs);
	}

	devm_kfree(pc->dev, maps);
}

static int bcm2708_pctl_dt_node_to_map_func(struct bcm2708_pinctrl *pc,
		u32 pin, const char *fname,
		struct pinctrl_map **maps)
{
	int i;
	enum bcm2708_fsel fsel = -1;
	struct pinctrl_map *map = *maps;

	for (i = 0; i < ARRAY_SIZE(bcm2708_functions); i++) {
		if (strcmp(fname, bcm2708_functions[i]))
			continue;

		fsel = i;
		break;
	}

	if (fsel == -1)
		return -EINVAL;

	map->type = PIN_MAP_TYPE_MUX_GROUP;
	map->data.mux.group = bcm2708_gpio_groups[pin];
	map->data.mux.function = bcm2708_functions[fsel];

	(*maps)++;

	dev_dbg(pc->dev, "mapping group %s func %s\n",
			map->data.mux.group,
			map->data.mux.function);

	return 0;
}

static int bcm2708_pctl_dt_node_to_map(struct pinctrl_dev *pctldev,
		struct device_node *np_config,
		struct pinctrl_map **map, unsigned *num_maps)
{
	struct bcm2708_pinctrl *pc = pinctrl_dev_get_drvdata(pctldev);
	struct property *pins, *function;
	bool func_per_pin;
	int num_funcs, our_num_maps, num_pins, err;
	struct pinctrl_map *maps, *cur_map;
	const __be32 *p;
	u32 pin;
	const char *fname = NULL;

	pins = of_find_property(np_config, "broadcom,pins", NULL);
	if (!pins) {
		dev_err(pc->dev, "%s: missing broadcom,pins property\n",
				np_config->full_name);
		return -EINVAL;
	}

	function = of_find_property(np_config, "broadcom,function", NULL);
	if (!pins) {
		dev_err(pc->dev, "%s: missing broadcom,function property\n",
				np_config->full_name);
		return -EINVAL;
	}

	num_funcs = of_property_count_strings(np_config, "broadcom,function");
	num_pins = pins->length / sizeof(u32);
	our_num_maps = num_pins; /* FIXME: until we can do pinconf */

	/* broadcom,function is an optional property */
	if (num_funcs == 1)
		func_per_pin = false; /* same function for all pins */
	else if (num_funcs == num_pins)
		func_per_pin = true; /* one function per pin */
	else {
		dev_err(pc->dev, "%s: broadcom,function must have either 1 string or as many strings as there are pins\n",
				np_config->full_name);
		return -EINVAL;
	}

	cur_map = maps = devm_kzalloc(pc->dev, our_num_maps * sizeof(*maps),
			GFP_KERNEL);
	if (!maps)
		return -ENOMEM;

	for (p = of_prop_next_u32(pins, NULL, &pin); p;
			p = of_prop_next_u32(pins, p, &pin)) {
		if (pin >= ARRAY_SIZE(bcm2708_gpio_pins)) {
			dev_err(pc->dev, "%s: pin %d out of bounds\n",
					np_config->full_name, pin);
			err = -EINVAL;
			goto out;
		}

		if (!fname || func_per_pin)
			fname = of_prop_next_string(function, fname);

		err = bcm2708_pctl_dt_node_to_map_func(pc, pin, fname,
				&cur_map);
		if (err)
			goto out;
	}

	*map = maps;
	*num_maps = our_num_maps;

	return 0;

out:
	bcm2708_pctl_dt_free_map(pctldev, maps, our_num_maps);
	return err;
}

static struct pinctrl_ops bcm2708_pctl_ops = {
	.get_groups_count = bcm2708_pctl_get_groups_count,
	.get_group_name = bcm2708_pctl_get_group_name,
	.get_group_pins = bcm2708_pctl_get_group_pins,
	.pin_dbg_show = bcm2708_pctl_pin_dbg_show,
	.dt_node_to_map = bcm2708_pctl_dt_node_to_map,
	.dt_free_map = bcm2708_pctl_dt_free_map,
};

static int bcm2708_pmx_get_functions_count(struct pinctrl_dev *pctldev)
{
	return BCM2708_FSEL_COUNT;
}

static const char *bcm2708_pmx_get_function_name(struct pinctrl_dev *pctldev,
		unsigned selector)
{
	if (selector >= BCM2708_FSEL_COUNT)
		return ERR_PTR(-EINVAL);

	return bcm2708_functions[selector];
}

static int bcm2708_pmx_get_function_groups(struct pinctrl_dev *pctldev,
		unsigned selector,
		const char * const **groups,
		unsigned * const num_groups)
{
	if (selector >= BCM2708_FSEL_COUNT)
		return -EINVAL;

	/* every pin can do every function */
	*groups = bcm2708_gpio_groups;
	*num_groups = ARRAY_SIZE(bcm2708_gpio_groups);

	return 0;
}

static int bcm2708_pmx_enable(struct pinctrl_dev *pctldev,
		unsigned func_selector,
		unsigned group_selector)
{
	struct bcm2708_pinctrl *pc = pinctrl_dev_get_drvdata(pctldev);

	if (bcm2708_warn_readonly(pc, group_selector, func_selector))
		return -EINVAL;

	bcm2708_pinctrl_fsel_set(pc, group_selector, func_selector);

	return 0;
}

static void bcm2708_pmx_disable(struct pinctrl_dev *pctldev,
		unsigned func_selector,
		unsigned group_selector)
{
	struct bcm2708_pinctrl *pc = pinctrl_dev_get_drvdata(pctldev);

	if (test_bit(group_selector, pc->readonly_map))
		return;

	/* disable by setting to GPIO_IN */
	bcm2708_pinctrl_fsel_set(pc, group_selector, BCM2708_FSEL_GPIO_IN);
}

static int bcm2708_pmx_gpio_request_enable(struct pinctrl_dev *pctldev,
		struct pinctrl_gpio_range *range,
		unsigned offset)
{
	return bcm2708_pmx_enable(pctldev, BCM2708_FSEL_GPIO_IN, offset);
}

static void bcm2708_pmx_gpio_disable_free(struct pinctrl_dev *pctldev,
		struct pinctrl_gpio_range *range,
		unsigned offset)
{
	return bcm2708_pmx_disable(pctldev, BCM2708_FSEL_GPIO_IN, offset);
}

static int bcm2708_pmx_gpio_set_direction(struct pinctrl_dev *pctldev,
		struct pinctrl_gpio_range *range,
		unsigned offset,
		bool input)
{
	struct bcm2708_pinctrl *pc = pinctrl_dev_get_drvdata(pctldev);
	enum bcm2708_fsel fsel = input ?
		BCM2708_FSEL_GPIO_IN : BCM2708_FSEL_GPIO_OUT;

	if (bcm2708_warn_readonly(pc, offset, fsel))
		return -EINVAL;

	bcm2708_pinctrl_fsel_set(pc, offset, fsel);

	return 0;
}

static struct pinmux_ops bcm2708_pmx_ops = {
	.get_functions_count = bcm2708_pmx_get_functions_count,
	.get_function_name = bcm2708_pmx_get_function_name,
	.get_function_groups = bcm2708_pmx_get_function_groups,
	.enable = bcm2708_pmx_enable,
	.disable = bcm2708_pmx_disable,
	.gpio_request_enable = bcm2708_pmx_gpio_request_enable,
	.gpio_disable_free = bcm2708_pmx_gpio_disable_free,
	.gpio_set_direction = bcm2708_pmx_gpio_set_direction,
};

int bcm2708_conf_pin_config_get(struct pinctrl_dev *pctldev,
		unsigned pin,
		unsigned long *config)
{
	/* FIXME */
	return -EINVAL;
}

int bcm2708_conf_pin_config_set(struct pinctrl_dev *pctldev,
		unsigned pin,
		unsigned long config)
{
	/* FIXME */
	return -EINVAL;
}

/*
void bcm2708_conf_pin_config_dbg_show(struct pinctrl_dev *pctldev,
		struct seq_file *s,
		unsigned offset)
{

}

void bcm2708_conf_pin_config_config_dbg_show(struct pinctrl_dev *pctldev,
		struct seq_file *s,
		unsigned long config)
{

}
*/

static struct pinconf_ops bcm2708_conf_ops = {
	.is_generic = true,
	.pin_config_get = bcm2708_conf_pin_config_get,
	.pin_config_set = bcm2708_conf_pin_config_set,
/*	.pin_config_dbg_show = bcm2708_conf_pin_config_dbg_show,*/
/*	.pin_config_config_dbg_show = bcm2708_conf_pin_config_config_dbg_show,*/
};

static struct pinctrl_desc bcm2708_pinctrl_desc = {
	.name = MODULE_NAME,
	.pins = bcm2708_gpio_pins,
	.npins = ARRAY_SIZE(bcm2708_gpio_pins),
	.pctlops = &bcm2708_pctl_ops,
	.pmxops = &bcm2708_pmx_ops,
/*	.confops = &bcm2708_conf_ops,*/
	.owner = THIS_MODULE,
};

static struct pinctrl_gpio_range bcm2708_pinctrl_gpio_range = {
	.base = 0,
	.pin_base = 0,
	.npins = ARRAY_SIZE(bcm2708_gpio_pins),
/*	.gc = &bcm2708_gpio_chip,*/
};

static int __devinit bcm2708_pinctrl_probe(struct platform_device *pdev)
{
	struct resource iomem;
	int err;
	struct bcm2708_pinctrl *pc;
	struct property *read_only;
	const __be32 *pin_p;
	u32 pin;

	err = of_address_to_resource(pdev->dev.of_node, 0, &iomem);
	if (err) {
		dev_err(&pdev->dev, "could not get IO memory\n");
		return err;
	}

	pc = devm_kzalloc(&pdev->dev, sizeof(*pc), GFP_KERNEL);
	if (!pc)
		return -ENOMEM;

	pc->dev = &pdev->dev;

	of_property_for_each_u32(pdev->dev.of_node, "broadcom,read-only",
			read_only, pin_p, pin) {
		if (pin >= BCM2708_NUM_GPIOS) {
			dev_err(pc->dev,
				"cannot set %d read-only: out of bounds\n",
				pin);
			return -EINVAL;
		}

		dev_dbg(pc->dev, "setting pin %d read-only\n", pin);
		set_bit(pin, pc->readonly_map);
	}

	pc->base = devm_request_and_ioremap(&pdev->dev, &iomem);
	if (!pc->base)
		return -EADDRNOTAVAIL;

	pc->pctl_dev = pinctrl_register(&bcm2708_pinctrl_desc, pc->dev, pc);
	if (IS_ERR(pc->pctl_dev))
		return PTR_ERR(pc->pctl_dev);

	pinctrl_add_gpio_range(pc->pctl_dev, &bcm2708_pinctrl_gpio_range);

	platform_set_drvdata(pdev, pc);

	return 0;
}

static int __devexit bcm2708_pinctrl_remove(struct platform_device *pdev)
{
	struct bcm2708_pinctrl *pc = platform_get_drvdata(pdev);

	pinctrl_remove_gpio_range(pc->pctl_dev, &bcm2708_pinctrl_gpio_range);
	pinctrl_unregister(pc->pctl_dev);

	return 0;
}

static struct of_device_id bcm2708_pinctrl_match[] __devinitconst = {
	{ .compatible = "broadcom,bcm2708-gpio" },
	{}
};
MODULE_DEVICE_TABLE(of, bcm2708_pinctrl_match);

static struct platform_driver bcm2708_pinctrl_driver = {
	.probe = bcm2708_pinctrl_probe,
	.remove = bcm2708_pinctrl_remove,
	.driver = {
		.name = MODULE_NAME,
		.owner = THIS_MODULE,
		.of_match_table = bcm2708_pinctrl_match,
	},
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

MODULE_AUTHOR("Chris Boot & Simon Arlott");
MODULE_DESCRIPTION("BCM2708 Pin control driver");
MODULE_LICENSE("GPL");
