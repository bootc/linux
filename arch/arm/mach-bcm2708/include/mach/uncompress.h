/*
 *  Copyright (C) 2010 Broadcom
 *  Copyright (C) 2003 ARM Limited
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

#include <linux/io.h>
#include <linux/amba/serial.h>
#include <mach/hardware.h>

#define UART0_BASE BCM2708_DEBUG_PHYS
#define BCM2708_UART_DR	UART0_BASE + UART01x_DR
#define BCM2708_UART_FR	UART0_BASE + UART01x_FR
#define BCM2708_UART_CR UART0_BASE + UART011_CR

/*
 * This does not append a newline
 */
static inline void putc(int c)
{
	while (__raw_readl(BCM2708_UART_FR) & UART01x_FR_TXFF)
		barrier();

	__raw_writel(c, BCM2708_UART_DR);
}

static inline void flush(void)
{
	int fr;

	do {
		fr = __raw_readl(BCM2708_UART_FR);
		barrier();
	} while ((fr & (UART011_FR_TXFE | UART01x_FR_BUSY)) != UART011_FR_TXFE);
}

/*
 * nothing to do
 */
#define arch_decomp_setup()
#define arch_decomp_wdog()
