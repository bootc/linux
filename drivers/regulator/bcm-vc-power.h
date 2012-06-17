/*
 * Copyright (C) 2010 Broadcom
 * Copyright 2012 Simon Arlott
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _BCM_VC_POWER_H
#define _BCM_VC_POWER_H

struct bcm_vc_power_dev;

bool bcm_vc_power_is_user(struct device_node *node);

/*
 * @node: calling node
 * @pname: property name for power phandle (NULL for default)
 * @pindex: property name for device index (NULL for default)
 *
 * Returns an error pointer if not found, otherwise holds a reference to the
 * device that must be put back with bcm_vc_power_put.
 */
struct bcm_vc_power_dev *bcm_vc_power_get(struct device_node *node,
	const char *pname, const char *pindex);
void bcm_vc_power_put(struct bcm_vc_power_dev *dev);

int bcm_vc_power_on(struct bcm_vc_power_dev *dev);
int bcm_vc_power_state(struct bcm_vc_power_dev *dev);
void bcm_vc_power_off(struct bcm_vc_power_dev *dev);

#endif
