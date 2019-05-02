// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>

#include <xen/xen.h>
#include <xen/xenhost.h>
#include <xen/features.h>
#include <xen/interface/features.h>

#include "xen-ops.h"

void xen_hvm_post_suspend(int suspend_cancelled)
{
	if (!suspend_cancelled) {
		xenhost_t **xh;

		for_each_xenhost(xh)
			xenhost_setup_shared_info(*xh);
		xen_vcpu_restore();
	}
	xen_callback_vector();
	xen_unplug_emulated_devices();
}
