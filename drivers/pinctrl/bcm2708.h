/*
 * Copyright 2012 Simon Arlott
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
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

#ifndef _PINCTRL_BCM2708_H
#define _PINCTRL_BCM2708_H

#include <linux/device.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/platform_device.h>
#include <linux/sysfs.h>
#include <linux/pinctrl/pinctrl.h>
#include <linux/pinctrl/pinmux.h>
#include <linux/pinctrl/pinconf.h>

/*
 * The function selections are GPIOs + ALTs so the register layout would change
 * if the number of ALTs changes (currently 3 bits per pin).
 */
#define ALTS		6

/*
 * The maximum pins we could support is 70 before the register layout would
 * need to change.
 */
#define MAX_PINS	70

enum pin_fsel {
	FSEL_NONE = -1,
	FSEL_GPIO_IN,	/* 000 */
	FSEL_GPIO_OUT,	/* 001 */
	FSEL_ALT_BASE,
	FSEL_ALT5 = 2,	/* 010 */
	FSEL_ALT4,	/* 011 */
	FSEL_ALT0,	/* 100 */
	FSEL_ALT1,	/* 101 */
	FSEL_ALT2,	/* 110 */
	FSEL_ALT3,	/* 111 */
	FSELS
};

#define NAME_LEN	64
#define NAME_SPLIT	"|"

#define MUX_FUNCTION	"BCM2708"

enum def_pull { PULL_NONE, PULL_LOW, PULL_HIGH };

struct bcm2708_pinctrl;

struct bcm2708_pinctrl_attr {
	struct bcm2708_pinctrl *pc;
	int pin;
	struct device_attribute dev;
};

struct bcm2708_pinmux;

struct bcm2708_pinmux_attr {
	struct bcm2708_pinctrl *pc;
	struct bcm2708_pinmux *pm;
	struct device_attribute dev;
};

struct bcm2708_pinmux {
	struct list_head list;
	char *name;
	struct bcm2708_pinmux_attr attr;
	int count;

	/* pinctrl needs an array of pins */
	unsigned *pins;
	enum pin_fsel *fsel;
};

struct bcm2708_pinctrl {
	struct device *dev;
	struct mutex lock;
	bool active;

	struct resource res;
	void __iomem *base;

	int nr_pins;
	const char ***gpio;
	const char **pins;
	struct list_head groups;
	int nr_groups;
	u32 *pull;
	bool *input_only;

	/* sysfs */
	struct bcm2708_pinctrl_attr *attr_gpio;
	struct bcm2708_pinctrl_attr *attr_pins;
	bool *pm_locked;
	bool *usr_locked;

	/* pinctrl, pinmux */
	struct bcm2708_pinmux **grpidx;
	const char **grpnam;
	struct pinctrl_pin_desc *pindesc;
	struct pinctrl_map *pinmap;
	int nr_pinmaps;

	struct pinctrl_dev *pctl;
	struct pinctrl_desc desc;
	struct pinctrl_ops pctlops;
	struct pinmux_ops pmxops;
	struct pinconf_ops confops;
	struct pinctrl_gpio_range gpio_range;
};

static inline int to_alt_index(enum pin_fsel value)
{
	switch (value) {
	case FSEL_ALT0: return 0;
	case FSEL_ALT1: return 1;
	case FSEL_ALT2: return 2;
	case FSEL_ALT3: return 3;
	case FSEL_ALT4: return 4;
	case FSEL_ALT5: return 5;
	default:
		WARN_ON(1);
		break;
	}
	return 0;
}

static inline enum pin_fsel to_fsel_value(int index)
{
	switch (index) {
	case 0: return FSEL_ALT0;
	case 1: return FSEL_ALT1;
	case 2: return FSEL_ALT2;
	case 3: return FSEL_ALT3;
	case 4: return FSEL_ALT4;
	case 5: return FSEL_ALT5;
	default:
		WARN_ON(1);
		break;
	}
	return FSEL_ALT0;
}

/* io */
extern enum pin_fsel bcm2708_pinctrl_fsel_get(struct bcm2708_pinctrl *pc,
	unsigned p);
extern void bcm2708_pinctrl_fsel_set(struct bcm2708_pinctrl *pc, unsigned p,
	enum pin_fsel set);

/* of */
extern struct bcm2708_pinctrl __devinit *bcm2708_pinctrl_of_init(
	struct platform_device *pdev);
extern void bcm2708_pinctrl_of_free(struct bcm2708_pinctrl *pc);

/* pctrl */
extern int bcm2708_pinctrl_get_groups_count(struct pinctrl_dev *pctl);
extern const char *bcm2708_pinctrl_get_group_name(struct pinctrl_dev *pctl,
	unsigned selector);
extern int bcm2708_pinctrl_get_group_pins(struct pinctrl_dev *pctl,
	unsigned selector, const unsigned **pins, unsigned *num_pins);
extern int bcm2708_pinmux_request(struct pinctrl_dev *pctl, unsigned offset);
extern int bcm2708_pinmux_free(struct pinctrl_dev *pctl, unsigned offset);
extern int bcm2708_pinmux_get_functions_count(struct pinctrl_dev *pctl);
extern const char *bcm2708_pinmux_get_function_name(struct pinctrl_dev *pctl,
	unsigned selector);
extern int bcm2708_pinmux_get_function_groups(struct pinctrl_dev *pctl,
	unsigned selector, const char * const **groups,
	unsigned * const num_groups);
extern int bcm2708_pinmux_enable(struct pinctrl_dev *pctl,
	unsigned func_selector, unsigned group_selector);
extern void bcm2708_pinmux_disable(struct pinctrl_dev *pctl,
	unsigned func_selector, unsigned group_selector);
extern int bcm2708_pinmux_gpio_request_enable(struct pinctrl_dev *pctl,
	struct pinctrl_gpio_range *range, unsigned offset);
extern void bcm2708_pinmux_gpio_disable_free(struct pinctrl_dev *pctl,
	struct pinctrl_gpio_range *range, unsigned offset);
extern int bcm2708_pinmux_gpio_set_direction(struct pinctrl_dev *pctl,
	struct pinctrl_gpio_range *range, unsigned offset, bool input);

/* sysfs */
extern int bcm2708_pinctrl_sysfs_register(struct bcm2708_pinctrl *pc);
extern void bcm2708_pinctrl_sysfs_unregister(struct bcm2708_pinctrl *pc);

#endif
