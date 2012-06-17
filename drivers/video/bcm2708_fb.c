/*
 *  linux/drivers/video/bcm2708_fb.c
 *
 * Copyright (C) 2010 Broadcom
 * Copyright 2012 Simon Arlott
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file COPYING in the main directory of this archive
 * for more details.
 *
 * Broadcom simple framebuffer driver
 *
 * This file is derived from cirrusfb.c
 * Copyright 1999-2001 Jeff Garzik <jgarzik@pobox.com>
 *
 */

#include <linux/bcm-mbox.h>
#include <linux/console.h>
#include <linux/dma-mapping.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/fb.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>

/* This is limited to 16 characters when displayed by X startup */
static const char *bcm2708_name = "BCM2708 FB";

#define DRIVER_NAME "bcm2708_fb"

/* this data structure describes each frame buffer device we find */
struct fbinfo_s {
	u32 xres, yres, xres_virtual, yres_virtual;
	u32 pitch, bpp;
	u32 xoffset, yoffset;
	u32 base;
	u32 screen_size;
};

struct bcm2708_fb {
	struct fb_info fb;
	struct device *dev;
	struct bcm_mbox_chan *mbox;
	struct fbinfo_s *info;
	dma_addr_t dma;
	u32 cmap[16];
};

#define to_bcm2708_fb(info)	container_of(info, struct bcm2708_fb, fb)

static unsigned int fbwidth = 800;
static unsigned int fbheight = 480;
static unsigned int fbdepth = 16;

module_param(fbwidth, uint, 0444);
module_param(fbheight, uint, 0444);
module_param(fbdepth, uint, 0444);

MODULE_PARM_DESC(fbwidth, "Width of ARM Framebuffer");
MODULE_PARM_DESC(fbheight, "Height of ARM Framebuffer");
MODULE_PARM_DESC(fbdepth, "Bit depth of ARM Framebuffer");

static int bcm2708_fb_set_bitfields(struct fb_var_screeninfo *var)
{
	int ret = 0;

	memset(&var->transp, 0, sizeof(var->transp));

	var->red.msb_right = 0;
	var->green.msb_right = 0;
	var->blue.msb_right = 0;

	switch (var->bits_per_pixel) {
	case 1:
	case 2:
	case 4:
	case 8:
		var->red.length = var->bits_per_pixel;
		var->red.offset = 0;
		var->green.length = var->bits_per_pixel;
		var->green.offset = 0;
		var->blue.length = var->bits_per_pixel;
		var->blue.offset = 0;
		break;
	case 16:
		var->red.length = 5;
		var->blue.length = 5;
		/*
		 * Green length can be 5 or 6 depending whether
		 * we're operating in RGB555 or RGB565 mode.
		 */
		if (var->green.length != 5 && var->green.length != 6)
			var->green.length = 6;
		break;
	case 24:
		var->red.length = 8;
		var->blue.length = 8;
		var->green.length = 8;
		break;
	case 32:
		var->red.length = 8;
		var->green.length = 8;
		var->blue.length = 8;
		var->transp.length = 8;
		break;
	default:
		ret = -EINVAL;
		break;
	}

	/*
	 * >= 16bpp displays have separate colour component bitfields
	 * encoded in the pixel data.  Calculate their position from
	 * the bitfield length defined above.
	 */
	if (ret == 0 && var->bits_per_pixel >= 24) {
		var->red.offset = 0;
		var->green.offset = var->red.offset + var->red.length;
		var->blue.offset = var->green.offset + var->green.length;
		var->transp.offset = var->blue.offset + var->blue.length;
	} else if (ret == 0 && var->bits_per_pixel >= 16) {
		var->blue.offset = 0;
		var->green.offset = var->blue.offset + var->blue.length;
		var->red.offset = var->green.offset + var->green.length;
		var->transp.offset = var->red.offset + var->red.length;
	}

	return ret;
}

/* @info: input
 * @var: output
 */
static int bcm2708_fb_check_var(struct fb_var_screeninfo *var,
				struct fb_info *info)
{
	struct bcm2708_fb *fb = to_bcm2708_fb(info);
	int yres;

	if (!var->bits_per_pixel)
		var->bits_per_pixel = 16;

	if (bcm2708_fb_set_bitfields(var) != 0) {
		dev_err(fb->dev, "invalid bits_per_pixel %d\n",
			var->bits_per_pixel);
		return -EINVAL;
	}

	if (var->xres_virtual < var->xres)
		var->xres_virtual = var->xres;

	/* use highest possible virtual resolution */
	if (var->yres_virtual == -1) {
		var->yres_virtual = 480;

		dev_warn(fb->dev, "virtual resolution set to maximum of %dx%d\n",
		     var->xres_virtual, var->yres_virtual);
	}
	if (var->yres_virtual < var->yres)
		var->yres_virtual = var->yres;

	if (var->xoffset < 0)
		var->xoffset = 0;
	if (var->yoffset < 0)
		var->yoffset = 0;

	/* truncate xoffset and yoffset to maximum if too high */
	if (var->xoffset > var->xres_virtual - var->xres)
		var->xoffset = var->xres_virtual - var->xres - 1;
	if (var->yoffset > var->yres_virtual - var->yres)
		var->yoffset = var->yres_virtual - var->yres - 1;

	yres = var->yres;
	if (var->vmode & FB_VMODE_DOUBLE)
		yres *= 2;
	else if (var->vmode & FB_VMODE_INTERLACED)
		yres = (yres + 1) / 2;

	if (yres > 1200) {
		/* TODO: support yres > 1200 */
		dev_err(fb->dev, "yres > 1200 unusupported\n");
		return -EINVAL;
	}

	return 0;
}

static int bcm2708_fb_set_par(struct fb_info *info)
{
	uint32_t val = 0;
	struct bcm2708_fb *fb = to_bcm2708_fb(info);
	struct fbinfo_s *fbinfo = fb->info;
	int ret;

	fbinfo->xres = info->var.xres;
	fbinfo->yres = info->var.yres;
	fbinfo->xres_virtual = info->var.xres_virtual;
	fbinfo->yres_virtual = info->var.yres_virtual;
	fbinfo->bpp = info->var.bits_per_pixel;
	fbinfo->xoffset = info->var.xoffset;
	fbinfo->yoffset = info->var.yoffset;

	/* filled in by VC */
	fbinfo->base = 0;
	fbinfo->pitch = 0;

	/* ensure last write to fbinfo is visible to GPU */
	wmb();

	/* inform vc about new framebuffer and get response */
	bcm_mbox_clear(fb->mbox);
	ret = bcm_mbox_call_timeout(fb->mbox, fb->dma, &val, 2 * HZ);
	if (ret)
		dev_err(fb->dev, "error communicating with VideoCore (%d)",
				ret);

	/* ensure GPU writes are visible to us */
	rmb();

	if (ret != 0 || val != 0) {
		/* the console may currently be locked */
		console_trylock();
		console_unlock();

		/* fbcon_init can't handle errors */
		panic(DRIVER_NAME ": VideoCore fatal error ret=%d val=%d\n",
				ret, val);
	}

	fb->fb.fix.line_length = fbinfo->pitch;

	if (info->var.bits_per_pixel <= 8)
		fb->fb.fix.visual = FB_VISUAL_PSEUDOCOLOR;
	else
		fb->fb.fix.visual = FB_VISUAL_TRUECOLOR;

	if (fb->fb.screen_base) {
		iounmap(fb->fb.screen_base);
		release_mem_region(fb->fb.fix.smem_start,
				fb->fb.fix.smem_len);
	}

	fb->fb.fix.smem_start = fbinfo->base;
	fb->fb.fix.smem_len = fbinfo->pitch * fbinfo->yres_virtual;
	if (!request_mem_region(fb->fb.fix.smem_start, fb->fb.fix.smem_len,
			dev_name(fb->dev))) {
		/* the console may currently be locked */
		console_trylock();
		console_unlock();

		/* fbcon_init can't handle errors */
		panic(DRIVER_NAME ": request_region failed for 0x%08lx+0x%08x\n",
				fb->fb.fix.smem_start, fb->fb.fix.smem_len);
	}

	fb->fb.screen_size = fbinfo->screen_size;
	fb->fb.screen_base = ioremap_wc(fb->fb.fix.smem_start,
			fb->fb.screen_size);
	if (!fb->fb.screen_base) {
		/* the console may currently be locked */
		console_trylock();
		console_unlock();

		/* fbcon_init can't handle errors */
		panic(DRIVER_NAME ": ioremap_wc failed at 0x%08lx+0x%08lx\n",
				fb->fb.fix.smem_start, fb->fb.screen_size);
	}
	return 0;
}

static inline u32 convert_bitfield(int val, struct fb_bitfield *bf)
{
	unsigned int mask = (1 << bf->length) - 1;

	return (val >> (16 - bf->length) & mask) << bf->offset;
}

static int bcm2708_fb_setcolreg(unsigned int regno, unsigned int red,
				unsigned int green, unsigned int blue,
				unsigned int transp, struct fb_info *info)
{
	struct bcm2708_fb *fb = to_bcm2708_fb(info);

	if (regno < 16)
		fb->cmap[regno] = convert_bitfield(transp, &fb->fb.var.transp)
			| convert_bitfield(blue, &fb->fb.var.blue)
			| convert_bitfield(green, &fb->fb.var.green)
			| convert_bitfield(red, &fb->fb.var.red);

	return (regno < 256) ? 0 : -EINVAL;
}

static int bcm2708_fb_blank(int blank_mode, struct fb_info *info)
{
	return -EPERM;
}

static struct fb_ops bcm2708_fb_ops = {
	.owner = THIS_MODULE,
	.fb_check_var = bcm2708_fb_check_var,
	.fb_set_par = bcm2708_fb_set_par,
	.fb_setcolreg = bcm2708_fb_setcolreg,
	.fb_blank = bcm2708_fb_blank,
	.fb_fillrect = cfb_fillrect,
	.fb_copyarea = cfb_copyarea,
	.fb_imageblit = cfb_imageblit
};

static int bcm2708_fb_register(struct bcm2708_fb *fb)
{
	int ret;

	fb->info = dmam_alloc_coherent(fb->dev, PAGE_ALIGN(sizeof(*fb->info)),
		&fb->dma, GFP_KERNEL);
	if (!fb->info) {
		dev_err(fb->dev, "unable to allocate fbinfo buffer\n");
		return -ENOMEM;
	}

	fb->fb.fbops = &bcm2708_fb_ops;
	fb->fb.flags = FBINFO_FLAG_DEFAULT;
	fb->fb.pseudo_palette = fb->cmap;

	strncpy(fb->fb.fix.id, bcm2708_name, sizeof(fb->fb.fix.id));
	fb->fb.fix.type = FB_TYPE_PACKED_PIXELS;
	fb->fb.fix.type_aux = 0;
	fb->fb.fix.xpanstep = 0;
	fb->fb.fix.ypanstep = 0;
	fb->fb.fix.ywrapstep = 0;
	fb->fb.fix.accel = FB_ACCEL_NONE;

	fb->fb.var.xres = fbwidth;
	fb->fb.var.yres = fbheight;
	fb->fb.var.xres_virtual = fbwidth;
	fb->fb.var.yres_virtual = fbheight;
	fb->fb.var.bits_per_pixel = fbdepth;
	fb->fb.var.vmode = FB_VMODE_NONINTERLACED;
	fb->fb.var.activate = FB_ACTIVATE_NOW;
	fb->fb.var.nonstd = 0;
	fb->fb.var.height = fbwidth;
	fb->fb.var.width = fbheight;
	fb->fb.var.accel_flags = 0;

	fb->fb.monspecs.hfmin = 0;
	fb->fb.monspecs.hfmax = 100000;
	fb->fb.monspecs.vfmin = 0;
	fb->fb.monspecs.vfmax = 400;
	fb->fb.monspecs.dclkmin = 1000000;
	fb->fb.monspecs.dclkmax = 100000000;

	bcm2708_fb_set_bitfields(&fb->fb.var);

	/* Allocate colourmap */
	fb_set_var(&fb->fb, &fb->fb.var);

	dev_info(fb->dev, "registering framebuffer (%dx%d@%d)\n", fbwidth,
		fbheight, fbdepth);

	ret = register_framebuffer(&fb->fb);
	if (ret)
		dev_err(fb->dev, "error registering framebuffer (%d)\n", ret);
	return ret;
}

static void bcm2708_fb_of_prop(struct device_node *node, char *name,
	unsigned int *value)
{
	u32 tmp;
	if (!of_property_read_u32(node, name, &tmp) && tmp != 0)
		*value = tmp;
}

static int bcm2708_fb_probe(struct platform_device *of_dev)
{
	struct device_node *node = of_dev->dev.of_node;
	struct bcm2708_fb *fb = devm_kzalloc(&of_dev->dev,
		sizeof(*fb), GFP_KERNEL);
	char *name;
	int ret;

	if (!fb)
		return -ENOMEM;

	fb->dev = &of_dev->dev;
	fb->mbox = bcm_mbox_get(node, "broadcom,vc-mailbox", "broadcom,vc-channel");

	if (IS_ERR(fb->mbox)) {
		dev_err(fb->dev, "unable to find VideoCore mailbox (%ld)",
			PTR_ERR(fb->mbox));
		return PTR_ERR(fb->mbox);
	}

	name = bcm_mbox_name(fb->mbox);
	dev_info(fb->dev, "attached to mailbox %s\n", name);
	kfree(name);

	bcm2708_fb_of_prop(node, "broadcom,width", &fbwidth);
	bcm2708_fb_of_prop(node, "broadcom,height", &fbheight);
	bcm2708_fb_of_prop(node, "broadcom,depth", &fbdepth);

	ret = bcm2708_fb_register(fb);
	if (ret) {
		bcm_mbox_put(fb->mbox);
		return ret;
	}

	platform_set_drvdata(of_dev, fb);
	return 0;
}

static int bcm2708_fb_remove(struct platform_device *of_dev)
{
	struct bcm2708_fb *fb = platform_get_drvdata(of_dev);

	unregister_framebuffer(&fb->fb);
	if (fb->fb.screen_base) {
		release_mem_region(fb->fb.fix.smem_start,
				fb->fb.fix.smem_len);
		iounmap(fb->fb.screen_base);
	}

	bcm_mbox_put(fb->mbox);
	platform_set_drvdata(of_dev, NULL);
	return 0;
}

static struct of_device_id bcm2708_fb_dt_match[] __devinitconst = {
	{ .compatible = "broadcom,bcm2708-fb" },
	{}
};
MODULE_DEVICE_TABLE(of, bcm2708_fb_dt_match);

static struct platform_driver bcm2708_fb_driver = {
	.probe = bcm2708_fb_probe,
	.remove = bcm2708_fb_remove,
	.driver = {
		.name = DRIVER_NAME,
		.owner = THIS_MODULE,
		.of_match_table = bcm2708_fb_dt_match
	}
};
module_platform_driver(bcm2708_fb_driver);

MODULE_DESCRIPTION("BCM2708 framebuffer driver");
MODULE_LICENSE("GPL");
