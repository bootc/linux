/*
 * Copyright (C) 2010 Broadcom
 * Copyright 2012 Simon Arlott
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _BCM_MBOX_H
#define _BCM_MBOX_H

#include <linux/device.h>
#include <linux/types.h>

struct bcm_mbox_chan;

/*
 * @node: calling node
 * @pmbox: property name for mailbox phandle
 * @pchan: property name for channel index
 *
 * Returns an error pointer if not found, otherwise holds a reference to the
 * device that must be put back with bcm_mbox_put.
 */
extern struct bcm_mbox_chan *bcm_mbox_get(struct device_node *node,
	const char *pmbox, const char *pchan);
extern char *bcm_mbox_name(struct bcm_mbox_chan *mbox);
extern void bcm_mbox_put(struct bcm_mbox_chan *mbox);

extern int bcm_mbox_poll(struct bcm_mbox_chan *mbox, u32 *data28);
extern int bcm_mbox_read(struct bcm_mbox_chan *mbox, u32 *data28);
extern int bcm_mbox_read_interruptible(struct bcm_mbox_chan *mbox, u32 *data28);
extern int bcm_mbox_read_timeout(struct bcm_mbox_chan *mbox, u32 *data28,
	long jiffies);

extern int bcm_mbox_write(struct bcm_mbox_chan *mbox, u32 data28);
extern int bcm_mbox_call(struct bcm_mbox_chan *mbox,
	u32 out_data28, u32 *in_data28);
extern int bcm_mbox_call_interruptible(struct bcm_mbox_chan *mbox,
	u32 out_data28, u32 *in_data28);
extern int bcm_mbox_call_timeout(struct bcm_mbox_chan *mbox, u32 out_data28,
	u32 *in_data28, long jiffies);

extern int bcm_mbox_clear(struct bcm_mbox_chan *mbox);

#endif
