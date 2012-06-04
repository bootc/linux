/*
 * Driver for Broadcom BCM2708 GPIO unit (pinctl + GPIO)
 *
 * Copyright (C) 2012 Chris Boot, Simon Arlott
 *
 * This driver is inspired by:
 * pinctrl-nomadik.c, please see original file for copyright information
 * pinctrl-tegra.c, please see original file for copyright information
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
#include <linux/irq.h>
#include <linux/irqdesc.h>
#include <linux/irqdomain.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/pinctrl/pinctrl.h>
#include <linux/pinctrl/pinmux.h>
#include <linux/pinctrl/pinconf.h>
#include <linux/pinctrl/machine.h>
#include <linux/pinctrl/consumer.h>
#include <linux/platform_device.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/types.h>
#include "core.h"

#define MODULE_NAME "pinctrl-bcm2708"
#define BCM2708_NUM_GPIOS 54
#define BCM2708_NUM_BANKS 2

#define BCM2708_PIN_BITMAP_SZ \
	DIV_ROUND_UP(BCM2708_NUM_GPIOS, sizeof(unsigned long) * 8)

/* GPIO register offsets */
#define GPFSEL0		0x0	/* Function Select */
#define GPSET0		0x1c	/* Pin Output Set */
#define GPCLR0		0x28	/* Pin Output Clear */
#define GPLEV0		0x34	/* Pin Level */
#define GPEDS0		0x40	/* Pin Event Detect Status */
#define GPREN0		0x4c	/* Pin Rising Edge Detect Enable */
#define GPFEN0		0x58	/* Pin Falling Edge Detect Enable */
#define GPHEN0		0x64	/* Pin High Detect Enable */
#define GPLEN0		0x70	/* Pin Low Detect Enable */
#define GPAREN0		0x7c	/* Pin Async Rising Edge Detect */
#define GPAFEN0		0x88	/* Pin Async Falling Edge Detect */
#define GPPUD		0x94	/* Pin Pull-up/down Enable */
#define GPPUDCLK0	0x98	/* Pin Pull-up/down Enable Clock */

struct bcm2708_gpio_irqdata {
	struct bcm2708_pinctrl *pc;
	int bank;
};

struct bcm2708_pinctrl {
	struct device *dev;
	void __iomem *base;
	int irq[BCM2708_NUM_BANKS];

	unsigned long readonly_map[BCM2708_PIN_BITMAP_SZ];
	/* note: locking assumes each bank will have its own unsigned long */
	unsigned long masked_irq_map[BCM2708_PIN_BITMAP_SZ];
	unsigned int irq_type[BCM2708_NUM_GPIOS];

	struct pinctrl_dev *pctl_dev;
	struct irq_domain *irq_domain;
	struct gpio_chip gpio_chip;
	struct pinctrl_gpio_range gpio_range;

	struct bcm2708_gpio_irqdata irq_data[BCM2708_NUM_BANKS];
	spinlock_t irq_lock[BCM2708_NUM_BANKS];
};

static struct lock_class_key gpio_lock_class;

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

static const char *irq_type_names[] = {
	[IRQ_TYPE_NONE] = "none",
	[IRQ_TYPE_EDGE_RISING] = "edge-rising",
	[IRQ_TYPE_EDGE_FALLING] = "edge-falling",
	[IRQ_TYPE_EDGE_BOTH] = "edge-both",
	[IRQ_TYPE_LEVEL_HIGH] = "level-high",
	[IRQ_TYPE_LEVEL_LOW] = "level-low",
};

#define FSEL_REG(p)		(GPFSEL0 + (((p) / 10) * 4))
#define FSEL_SHIFT(p)		(((p) % 10) * 3)
#define GPIO_REG_OFFSET(p)	((p) / 32)
#define GPIO_REG_SHIFT(p)	((p) % 32)

static inline u32 bcm2708_gpio_rd(struct bcm2708_pinctrl *pc, unsigned reg)
{
	return readl(pc->base + reg);
}

static inline void bcm2708_gpio_wr(struct bcm2708_pinctrl *pc, unsigned reg,
		u32 val)
{
	writel(val, pc->base + reg);
}

static inline int bcm2708_gpio_get_bit(struct bcm2708_pinctrl *pc, unsigned reg,
		unsigned bit)
{
	void __iomem *addr = pc->base + reg + (GPIO_REG_OFFSET(bit) * 4);
	return (readl(addr) >> GPIO_REG_SHIFT(bit)) & 1;
}

/* note NOT a read/modify/write cycle */
static inline void bcm2708_gpio_set_bit(struct bcm2708_pinctrl *pc,
		unsigned reg, unsigned bit)
{
	void __iomem *addr = pc->base + reg + (GPIO_REG_OFFSET(bit) * 4);
	writel(BIT(GPIO_REG_SHIFT(bit)), addr);
}

static inline enum bcm2708_fsel bcm2708_pinctrl_fsel_get(
		struct bcm2708_pinctrl *pc, unsigned pin)
{
	u32 val = bcm2708_gpio_rd(pc, FSEL_REG(pin));
	enum bcm2708_fsel status = (val >> FSEL_SHIFT(pin)) & BCM2708_FSEL_MASK;

	dev_dbg(pc->dev, "get %08x (%u => %s)\n", val, pin,
			bcm2708_functions[status]);

	return status;
}

static inline void bcm2708_pinctrl_fsel_set(
		struct bcm2708_pinctrl *pc, unsigned pin,
		enum bcm2708_fsel fsel)
{
	u32 val = bcm2708_gpio_rd(pc, FSEL_REG(pin));
	enum bcm2708_fsel cur = (val >> FSEL_SHIFT(pin)) & BCM2708_FSEL_MASK;

	dev_dbg(pc->dev, "read %08x (%u => %s)\n", val, pin,
			bcm2708_functions[cur]);

	if (cur == fsel)
		return;

	if (cur != BCM2708_FSEL_GPIO_IN && fsel != BCM2708_FSEL_GPIO_IN) {
		/* always transition through GPIO_IN */
		val &= ~(BCM2708_FSEL_MASK << FSEL_SHIFT(pin));
		val |= BCM2708_FSEL_GPIO_IN << FSEL_SHIFT(pin);

		dev_dbg(pc->dev, "trans %08x (%u <= %s)\n", val, pin,
				bcm2708_functions[BCM2708_FSEL_GPIO_IN]);
		bcm2708_gpio_wr(pc, FSEL_REG(pin), val);
	}

	val &= ~(BCM2708_FSEL_MASK << FSEL_SHIFT(pin));
	val |= fsel << FSEL_SHIFT(pin);

	dev_dbg(pc->dev, "write %08x (%u <= %s)\n", val, pin,
			bcm2708_functions[fsel]);
	bcm2708_gpio_wr(pc, FSEL_REG(pin), val);
}

static inline bool bcm2708_check_readonly(struct bcm2708_pinctrl *pc, int pin,
		enum bcm2708_fsel fsel)
{
	enum bcm2708_fsel cur;

	/* we only care about pins marked read-only */
	if (!test_bit(pin, pc->readonly_map))
		return false;

	/* don't care if the requested state is the same as now */
	cur = bcm2708_pinctrl_fsel_get(pc, pin);
	if (fsel == cur)
		return false;

	return true;
}

static int bcm2708_gpio_request(struct gpio_chip *chip, unsigned offset)
{
	return pinctrl_request_gpio(chip->base + offset);
}

static void bcm2708_gpio_free(struct gpio_chip *chip, unsigned offset)
{
	pinctrl_free_gpio(chip->base + offset);
}

static int bcm2708_gpio_direction_input(struct gpio_chip *chip, unsigned offset)
{
	return pinctrl_gpio_direction_input(chip->base + offset);
}

static int bcm2708_gpio_get(struct gpio_chip *chip, unsigned offset)
{
	struct bcm2708_pinctrl *pc = dev_get_drvdata(chip->dev);

	return bcm2708_gpio_get_bit(pc, GPLEV0, offset);
}

static int bcm2708_gpio_direction_output(struct gpio_chip *chip,
		unsigned offset, int value)
{
	return pinctrl_gpio_direction_output(chip->base + offset);
}

static void bcm2708_gpio_set(struct gpio_chip *chip, unsigned offset, int value)
{
	struct bcm2708_pinctrl *pc = dev_get_drvdata(chip->dev);

	if (test_bit(offset, pc->readonly_map)) {
		dev_warn(pc->dev, "refusing to change value of read-only pin %d\n",
			offset);
		return;
	}

	bcm2708_gpio_set_bit(pc, value ? GPSET0 : GPCLR0, offset);
}

static int bcm2708_gpio_to_irq(struct gpio_chip *chip, unsigned offset)
{
	struct bcm2708_pinctrl *pc = dev_get_drvdata(chip->dev);

	return irq_linear_revmap(pc->irq_domain, offset);
}

static struct gpio_chip bcm2708_gpio_chip __devinitconst = {
	.label = MODULE_NAME,
	.owner = THIS_MODULE,
	.request = bcm2708_gpio_request,
	.free = bcm2708_gpio_free,
	.direction_input = bcm2708_gpio_direction_input,
	.get = bcm2708_gpio_get,
	.direction_output = bcm2708_gpio_direction_output,
	.set = bcm2708_gpio_set,
	.to_irq = bcm2708_gpio_to_irq,
	.base = 0,
	.ngpio = BCM2708_NUM_GPIOS,
	.can_sleep = 0,
};

static void bcm2708_gpio_irq_handler(unsigned int irq, struct irq_desc *desc)
{
	struct bcm2708_gpio_irqdata *irqdata = irq_desc_get_handler_data(desc);
	struct bcm2708_pinctrl *pc = irqdata->pc;
	int bank = irqdata->bank;
	unsigned long events;
	unsigned offset;

	events = bcm2708_gpio_rd(pc, GPEDS0 + bank * 4);
	for_each_set_bit(offset, &events, 32) {
		irq = irq_linear_revmap(pc->irq_domain, (32 * bank) + offset);
		generic_handle_irq(irq);
	}
}

static void bcm2708_gpio_irq_ack(struct irq_data *data)
{
	struct bcm2708_pinctrl *pc = irq_data_get_irq_chip_data(data);
	bcm2708_gpio_set_bit(pc, GPEDS0, irqd_to_hwirq(data));
}

static inline void __bcm2708_gpio_irq_config(struct bcm2708_pinctrl *pc,
	unsigned reg, unsigned offset, bool enable)
{
	void __iomem *addr = pc->base + reg + (GPIO_REG_OFFSET(offset) * 4);
	u32 value = readl(addr);
	if (enable)
		value |= BIT(GPIO_REG_SHIFT(offset));
	else
		value &= ~(BIT(GPIO_REG_SHIFT(offset)));
	writel(value, addr);
}

/* fast path for IRQ handler */
static void bcm2708_gpio_irq_config(struct bcm2708_pinctrl *pc,
	unsigned offset, bool enable)
{
	switch (pc->irq_type[offset]) {
	case IRQ_TYPE_EDGE_RISING:
		__bcm2708_gpio_irq_config(pc, GPREN0, offset, enable);
		break;

	case IRQ_TYPE_EDGE_FALLING:
		__bcm2708_gpio_irq_config(pc, GPFEN0, offset, enable);
		break;

	case IRQ_TYPE_EDGE_BOTH:
		__bcm2708_gpio_irq_config(pc, GPREN0, offset, enable);
		__bcm2708_gpio_irq_config(pc, GPFEN0, offset, enable);
		break;

	case IRQ_TYPE_LEVEL_HIGH:
		__bcm2708_gpio_irq_config(pc, GPHEN0, offset, enable);
		break;

	case IRQ_TYPE_LEVEL_LOW:
		__bcm2708_gpio_irq_config(pc, GPLEN0, offset, enable);
		break;
	}
}

static inline void __bcm2708_gpio_irq_mask(struct irq_data *data, bool ack)
{
	struct bcm2708_pinctrl *pc = irq_data_get_irq_chip_data(data);
	unsigned offset = irqd_to_hwirq(data);
	unsigned bank = GPIO_REG_OFFSET(offset);
	unsigned long flags;

	spin_lock_irqsave(&pc->irq_lock[bank], flags);
	set_bit(offset, pc->masked_irq_map);
	bcm2708_gpio_irq_config(pc, offset, false);

	if (ack)
		bcm2708_gpio_set_bit(pc, GPEDS0, offset);

	spin_unlock_irqrestore(&pc->irq_lock[bank], flags);
}

static void bcm2708_gpio_irq_mask(struct irq_data *data)
{
	__bcm2708_gpio_irq_mask(data, false);
}

static void bcm2708_gpio_irq_mask_ack(struct irq_data *data)
{
	__bcm2708_gpio_irq_mask(data, true);
}

static void bcm2708_gpio_irq_unmask(struct irq_data *data)
{
	struct bcm2708_pinctrl *pc = irq_data_get_irq_chip_data(data);
	unsigned offset = irqd_to_hwirq(data);
	unsigned bank = GPIO_REG_OFFSET(offset);
	unsigned long flags;

	spin_lock_irqsave(&pc->irq_lock[bank], flags);
	clear_bit(offset, pc->masked_irq_map);
	bcm2708_gpio_irq_config(pc, offset, true);
	spin_unlock_irqrestore(&pc->irq_lock[bank], flags);
}

static int __bcm2708_gpio_irq_set_type_masked(struct bcm2708_pinctrl *pc,
	unsigned offset, unsigned int type)
{
	switch (type) {
	case IRQ_TYPE_NONE:
	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_FALLING:
	case IRQ_TYPE_EDGE_BOTH:
	case IRQ_TYPE_LEVEL_HIGH:
	case IRQ_TYPE_LEVEL_LOW:
		pc->irq_type[offset] = type;
		break;

	default:
		return -EINVAL;
	}
	return 0;
}

/* slower path for reconfiguring IRQ type */
static int __bcm2708_gpio_irq_set_type_unmasked(struct bcm2708_pinctrl *pc,
	unsigned offset, unsigned int type)
{
	switch (type) {
	case IRQ_TYPE_NONE:
		if (pc->irq_type[offset] != type) {
			bcm2708_gpio_irq_config(pc, offset, false);
			pc->irq_type[offset] = type;
		}
		break;

	case IRQ_TYPE_EDGE_RISING:
		if (pc->irq_type[offset] == IRQ_TYPE_EDGE_BOTH) {
			/* RISING already enabled, disable FALLING */
			pc->irq_type[offset] = IRQ_TYPE_EDGE_FALLING;
			bcm2708_gpio_irq_config(pc, offset, false);
			pc->irq_type[offset] = type;
		} else if (pc->irq_type[offset] != type) {
			bcm2708_gpio_irq_config(pc, offset, false);
			pc->irq_type[offset] = type;
			bcm2708_gpio_irq_config(pc, offset, true);
		}
		break;

	case IRQ_TYPE_EDGE_FALLING:
		if (pc->irq_type[offset] == IRQ_TYPE_EDGE_BOTH) {
			/* FALLING already enabled, disable RISING */
			pc->irq_type[offset] = IRQ_TYPE_EDGE_RISING;
			bcm2708_gpio_irq_config(pc, offset, false);
			pc->irq_type[offset] = type;
		} else if (pc->irq_type[offset] != type) {
			bcm2708_gpio_irq_config(pc, offset, false);
			pc->irq_type[offset] = type;
			bcm2708_gpio_irq_config(pc, offset, true);
		}
		break;

	case IRQ_TYPE_EDGE_BOTH:
		if (pc->irq_type[offset] == IRQ_TYPE_EDGE_RISING) {
			/* RISING already enabled, enable FALLING too */
			pc->irq_type[offset] = IRQ_TYPE_EDGE_FALLING;
			bcm2708_gpio_irq_config(pc, offset, true);
			pc->irq_type[offset] = type;
		} else if (pc->irq_type[offset] == IRQ_TYPE_EDGE_FALLING) {
			/* FALLING already enabled, enable RISING too */
			pc->irq_type[offset] = IRQ_TYPE_EDGE_RISING;
			bcm2708_gpio_irq_config(pc, offset, true);
			pc->irq_type[offset] = type;
		} else if (pc->irq_type[offset] != type) {
			bcm2708_gpio_irq_config(pc, offset, false);
			pc->irq_type[offset] = type;
			bcm2708_gpio_irq_config(pc, offset, true);
		}
		break;

	case IRQ_TYPE_LEVEL_HIGH:
	case IRQ_TYPE_LEVEL_LOW:
		if (pc->irq_type[offset] != type) {
			bcm2708_gpio_irq_config(pc, offset, false);
			pc->irq_type[offset] = type;
			bcm2708_gpio_irq_config(pc, offset, true);
		}
		break;

	default:
		return -EINVAL;
	}
	return 0;
}

static int bcm2708_gpio_irq_set_type(struct irq_data *data, unsigned int type)
{
	struct bcm2708_pinctrl *pc = irq_data_get_irq_chip_data(data);
	unsigned offset = irqd_to_hwirq(data);
	unsigned bank = GPIO_REG_OFFSET(offset);
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&pc->irq_lock[bank], flags);

	if (test_bit(offset, pc->masked_irq_map))
		ret = __bcm2708_gpio_irq_set_type_masked(pc, offset, type);
	else
		ret = __bcm2708_gpio_irq_set_type_unmasked(pc, offset, type);

	spin_unlock_irqrestore(&pc->irq_lock[bank], flags);

	return ret;
}

static struct irq_chip bcm2708_gpio_irq_chip = {
	.name = "GPIO-event",
	.irq_ack = bcm2708_gpio_irq_ack,
	.irq_mask = bcm2708_gpio_irq_mask,
	.irq_mask_ack = bcm2708_gpio_irq_mask_ack,
	.irq_unmask = bcm2708_gpio_irq_unmask,
	.irq_set_type = bcm2708_gpio_irq_set_type,
};

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
	const char *fname = bcm2708_functions[fsel];
	int value = bcm2708_gpio_get_bit(pc, GPLEV0, offset);
	int irq = irq_find_mapping(pc->irq_domain, offset);

	seq_printf(s, "function %s %s; irq %d (%s)",
		fname, value ? "hi" : "lo",
		irq, irq_type_names[pc->irq_type[offset]]);

	if (test_bit(offset, pc->readonly_map))
		seq_puts(s, "; read-only");
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

	return 0;
}

static int bcm2708_pctl_dt_node_to_map(struct pinctrl_dev *pctldev,
		struct device_node *np_config,
		struct pinctrl_map **map, unsigned *num_maps)
{
	struct bcm2708_pinctrl *pc = pinctrl_dev_get_drvdata(pctldev);
	struct property *pins, *function;
	bool func_per_pin;
	int num_funcs, num_pins, err;
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
	num_pins = pins->length / 4;

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

	cur_map = maps = devm_kzalloc(pc->dev, num_pins * sizeof(*maps),
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
	*num_maps = num_pins;

	return 0;

out:
	bcm2708_pctl_dt_free_map(pctldev, maps, num_pins);
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

	struct pin_desc *desc = pin_desc_get(pctldev, group_selector);
	if (desc->gpio_owner)
		return -EBUSY;

	if (bcm2708_check_readonly(pc, group_selector, func_selector)) {
		dev_warn(pc->dev, "refusing to change mode of read-only pin %d\n",
			group_selector);
		return -EPERM;
	}

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
	struct bcm2708_pinctrl *pc = pinctrl_dev_get_drvdata(pctldev);

	struct pin_desc *desc = pin_desc_get(pctldev, offset);
	if (desc->mux_usecount)
		return -EBUSY;

	if (bcm2708_check_readonly(pc, offset, BCM2708_FSEL_GPIO_IN)) {
		dev_warn(pc->dev, "refusing to change mode of read-only pin %d\n",
			offset);
		return -EPERM;
	}

	bcm2708_pinctrl_fsel_set(pc, offset, BCM2708_FSEL_GPIO_IN);

	return 0;
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

	if (bcm2708_check_readonly(pc, offset, fsel)) {
		dev_warn(pc->dev, "refusing to change mode of read-only pin %d\n",
			offset);
		return -EPERM;
	}

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

static struct pinctrl_desc bcm2708_pinctrl_desc = {
	.name = MODULE_NAME,
	.pins = bcm2708_gpio_pins,
	.npins = ARRAY_SIZE(bcm2708_gpio_pins),
	.pctlops = &bcm2708_pctl_ops,
	.pmxops = &bcm2708_pmx_ops,
	.owner = THIS_MODULE,
};

static struct pinctrl_gpio_range bcm2708_pinctrl_gpio_range __devinitconst = {
	.name = "GPIO",
	.base = 0,
	.pin_base = 0,
	.npins = ARRAY_SIZE(bcm2708_gpio_pins),
};

static int __devinit bcm2708_pinctrl_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *np = dev->of_node;
	struct resource iomem;
	int err, i;
	struct bcm2708_pinctrl *pc;
	struct property *prop_ro;
	const __be32 *p;
	u32 pin;

	err = of_address_to_resource(np, 0, &iomem);
	if (err) {
		dev_err(dev, "could not get IO memory\n");
		return err;
	}

	pc = devm_kzalloc(dev, sizeof(*pc), GFP_KERNEL);
	if (!pc)
		return -ENOMEM;

	pc->dev = dev;

	of_property_for_each_u32(np, "broadcom,read-only", prop_ro, p, pin) {
		if (pin >= BCM2708_NUM_GPIOS) {
			dev_err(dev, "cannot set %d read-only: out of bounds\n",
				pin);
			return -EINVAL;
		}

		dev_dbg(dev, "setting pin %d read-only\n", pin);
		set_bit(pin, pc->readonly_map);
	}

	pc->base = devm_request_and_ioremap(&pdev->dev, &iomem);
	if (!pc->base)
		return -EADDRNOTAVAIL;

	pc->gpio_chip = bcm2708_gpio_chip;
	pc->gpio_chip.dev = dev;
	pc->gpio_chip.of_node = np;

	pc->irq_domain = irq_domain_add_linear(np, BCM2708_NUM_GPIOS,
			&irq_domain_simple_ops, NULL);
	if (!pc->irq_domain) {
		dev_err(dev, "could not create IRQ domain\n");
		return -ENOMEM;
	}

	for (i = 0; i < BCM2708_NUM_GPIOS; i++) {
		int irq = irq_create_mapping(pc->irq_domain, i);
		set_bit(i, pc->masked_irq_map);
		irq_set_lockdep_class(irq, &gpio_lock_class);
		irq_set_chip_and_handler(irq, &bcm2708_gpio_irq_chip,
				handle_level_irq);
		irq_set_chip_data(irq, pc);
		set_irq_flags(irq, IRQF_VALID);
	}

	for (i = 0; i < BCM2708_NUM_BANKS; i++) {
		unsigned long events;
		unsigned offset;

		/* clear event detection flags */
		bcm2708_gpio_wr(pc, GPREN0 + i * 4, 0);
		bcm2708_gpio_wr(pc, GPFEN0 + i * 4, 0);
		bcm2708_gpio_wr(pc, GPHEN0 + i * 4, 0);
		bcm2708_gpio_wr(pc, GPLEN0 + i * 4, 0);
		bcm2708_gpio_wr(pc, GPAREN0 + i * 4, 0);
		bcm2708_gpio_wr(pc, GPAFEN0 + i * 4, 0);

		/* clear all the events */
		events = bcm2708_gpio_rd(pc, GPEDS0 + i * 4);
		for_each_set_bit(offset, &events, 32)
			bcm2708_gpio_wr(pc, GPEDS0 + i * 4, BIT(offset));

		pc->irq[i] = irq_of_parse_and_map(np, i);
		pc->irq_data[i].pc = pc;
		pc->irq_data[i].bank = i;
		spin_lock_init(&pc->irq_lock[i]);

		irq_set_chained_handler(pc->irq[i], bcm2708_gpio_irq_handler);
		irq_set_handler_data(pc->irq[i], &pc->irq_data[i]);
	}

	err = gpiochip_add(&pc->gpio_chip);
	if (err) {
		dev_err(dev, "could not add GPIO chip\n");
		return err;
	}

	pc->pctl_dev = pinctrl_register(&bcm2708_pinctrl_desc, dev, pc);
	if (IS_ERR(pc->pctl_dev))
		return PTR_ERR(pc->pctl_dev);

	pc->gpio_range = bcm2708_pinctrl_gpio_range;
	pc->gpio_range.gc = &pc->gpio_chip;

	pinctrl_add_gpio_range(pc->pctl_dev, &pc->gpio_range);

	platform_set_drvdata(pdev, pc);

	return 0;
}

static int __devexit bcm2708_pinctrl_remove(struct platform_device *pdev)
{
	struct bcm2708_pinctrl *pc = platform_get_drvdata(pdev);

	pinctrl_remove_gpio_range(pc->pctl_dev, &pc->gpio_range);
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
