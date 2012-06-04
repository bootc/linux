/*
 * Copyright 2012 Simon Arlott
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <linux/bitops.h>
#include <linux/clockchips.h>
#include <linux/clocksource.h>
#include <linux/interrupt.h>
#include <linux/irqreturn.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <asm/sched_clock.h>
#include <asm/irq.h>

#include "time.h"

#define REG_CONTROL	0x00
#define REG_COUNTER_LO	0x04
#define REG_COUNTER_HI	0x08
#define REG_COMPARE(n)	(0x0c + (n) * 4)
#define MAX_TIMER	3
#define DEFAULT_TIMER	3

struct bcm2708_timer {
	void __iomem *control;
	void __iomem *compare;
	int index;
	struct clock_event_device evt;
	struct irqaction act;
};

static void __iomem *system_clock __read_mostly;

static u32 notrace bcm2708_sched_read(void)
{
	return readl_relaxed(system_clock);
}

static void bcm2708_time_set_mode(enum clock_event_mode mode,
	struct clock_event_device *evt_dev)
{
	switch (mode) {
	case CLOCK_EVT_MODE_ONESHOT:
	case CLOCK_EVT_MODE_UNUSED:
	case CLOCK_EVT_MODE_SHUTDOWN:
	case CLOCK_EVT_MODE_RESUME:
		break;
	default:
		WARN(1, "%s: unhandled event mode %d\n", __func__, mode);
		break;
	}
}

static int bcm2708_time_set_next_event(unsigned long event,
	struct clock_event_device *evt_dev)
{
	struct bcm2708_timer *timer = container_of(evt_dev,
		struct bcm2708_timer, evt);
	writel_relaxed(readl_relaxed(system_clock) + event,
		timer->compare);
	return 0;
}

static irqreturn_t bcm2708_time_interrupt(int irq, void *dev_id)
{
	struct bcm2708_timer *timer = dev_id;
	void (*event_handler)(struct clock_event_device *);
	if (readl_relaxed(timer->control) & timer->index) {
		writel_relaxed(timer->index, timer->control);

		event_handler = ACCESS_ONCE(timer->evt.event_handler);
		if (event_handler)
			event_handler(&timer->evt);
		return IRQ_HANDLED;
	} else {
		return IRQ_NONE;
	}
}

static struct of_device_id bcm2708_time_match[] __initconst = {
	{ .compatible = "broadcom,bcm2708-system-timer" },
	{}
};

void __init bcm2708_time_init(void)
{
	struct device_node *node;
	bool found = false;

	for_each_matching_node(node, bcm2708_time_match) {
		struct bcm2708_timer *timer;
		struct resource res;
		void __iomem *base;
		int irq;

		if (of_address_to_resource(node, 0, &res))
			continue;

		base = ioremap(res.start, resource_size(&res));
		if (!base) {
			printk(KERN_ERR "bcm2708: unable to map timer device\n");
			continue;
		}

		if (!request_region(res.start, resource_size(&res),
				node->full_name)) {
			printk(KERN_ERR "bcm2708: unable to request timer IO\n");
			continue;
		}

		if (!found) {
			system_clock = base + REG_COUNTER_LO;
			setup_sched_clock(bcm2708_sched_read, 32, 1000000);
		}

		clocksource_mmio_init(base + REG_COUNTER_LO, node->name,
			1000000, 300, 32, clocksource_mmio_readl_up);

		irq = irq_of_parse_and_map(node, DEFAULT_TIMER);
		if (irq <= 0) {
			printk(KERN_ERR "bcm2708: can't find IRQ for timer\n");
			continue;
		}

		timer = kzalloc(sizeof(*timer), GFP_KERNEL);
		if (!timer)
			panic("bcm2708: out of memory for timer device\n");

		timer->control = base + REG_CONTROL;
		timer->compare = base + REG_COMPARE(DEFAULT_TIMER);
		timer->index = BIT(DEFAULT_TIMER);
		timer->evt.name = node->name;
		timer->evt.rating = 300;
		timer->evt.features = CLOCK_EVT_FEAT_ONESHOT;
		timer->evt.set_mode = bcm2708_time_set_mode;
		timer->evt.set_next_event = bcm2708_time_set_next_event;
		timer->evt.cpumask = cpumask_of(0);
		timer->act.name = node->name;
		timer->act.flags = IRQF_TIMER | IRQF_SHARED;
		timer->act.dev_id = timer;
		timer->act.handler = bcm2708_time_interrupt;

		if (setup_irq(irq, &timer->act)) {
			printk(KERN_ERR "bcm2708: unable to setup timer IRQ\n");
			kfree(timer);
			continue;
		}

		clockevents_config_and_register(&timer->evt, 1000000, 0xf, 0xffffffff);

		printk(KERN_INFO "bcm2708: system timer at MMIO %#lx (irq = %d)\n",
			(unsigned long)res.start, irq);
		found = true;
	}

	if (!found)
		panic("can't find system timer\n");
}
