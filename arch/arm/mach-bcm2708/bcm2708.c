/*
 *  Copyright (C) 2010 Broadcom
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

#include <linux/init.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <asm/mach/arch.h>
#include <asm/mach/time.h>
#include <asm/mach/map.h>
#include <asm/mach-types.h>
#include <asm/system.h>
#include <asm/exception.h>
#include <mach/hardware.h>
#include <asm/hardware/timer-sp.h>

#include "../../../drivers/watchdog/bcm2708_wdog.h"
#include "clock.h"
#include "irq.h"
#include "time.h"

module_param_named(boardrev, system_rev, uint, 0);
module_param_named(serial, system_serial_low, uint, 0);

static struct map_desc bcm2708_io_desc[] __initdata = {
	{
		.virtual = BCM2708_DEBUG_VIRT,
		.pfn = __phys_to_pfn(BCM2708_DEBUG_PHYS),
		.length = BCM2708_DEBUG_SIZE,
		.type = MT_DEVICE
	}
};

void __init bcm2708_map_io(void)
{
	iotable_init(bcm2708_io_desc, ARRAY_SIZE(bcm2708_io_desc));
}

static void __init bcm2708_of_system(void)
{
	struct device_node *system = of_find_node_by_path("/system");

	if (system) {
		u32 rev;
		u64 serial;

		if (!of_property_read_u32(system, "revision", &rev))
			system_rev = rev;

		if (!of_property_read_u64(system, "serial", &serial)) {
			system_serial_low = (u32)serial;
			system_serial_high = (u32)(serial >> 32);
		}
	}
}

void __init bcm2708_init(void)
{
	int ret;

	bcm2708_of_system();
	bcm2708_init_clocks();

	ret = of_platform_populate(NULL, of_default_bus_match_table, NULL, NULL);
	if (ret) {
		printk(KERN_ERR "BCM2708 devicetree: %d\n", ret);
		BUG();
	}
}

static struct of_device_id sp804_match[] __initconst = {
	{ .compatible = "arm,sp804" },
	{}
};

static void __init bcm2708_timer_init(void)
{
	struct device_node *node;

	/* Disable the SP804 */
	for_each_matching_node(node, sp804_match) {
		sp804_disable(of_iomap(node, 0));
	}

	bcm2708_time_init();
}

struct sys_timer bcm2708_timer = {
	.init = bcm2708_timer_init
};

static const char *bcm2708_compat[] = {
	"broadcom,bcm2708",
	NULL
};

MACHINE_START(BCM2708, "BCM2708")
	/* Maintainer: Broadcom Europe Ltd. */
	.init_machine = bcm2708_init,
	.map_io = bcm2708_map_io,
	.init_irq = bcm2708_init_irq,
	.handle_irq = armctrl_handle_irq,
	.timer = &bcm2708_timer,
	.restart = bcm2708_wdog_restart,
	.dt_compat = bcm2708_compat
MACHINE_END
