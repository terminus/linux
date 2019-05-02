// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>

#include <asm/fixmap.h>

#include <asm/xen/hypercall.h>
#include <asm/xen/page.h>

#include "xen-ops.h"

void xen_pv_pre_suspend(void)
{
	xenhost_t **xh;

	xen_mm_pin_all();

	xen_start_info->store_mfn = mfn_to_pfn(xen_start_info->store_mfn);
	xen_start_info->console.domU.mfn =
		mfn_to_pfn(xen_start_info->console.domU.mfn);

	BUG_ON(!irqs_disabled());

	for_each_xenhost(xh)
		xenhost_reset_shared_info(*xh);
}

void xen_pv_post_suspend(int suspend_cancelled)
{
	xenhost_t **xh;

	xen_build_mfn_list_list();
	for_each_xenhost(xh)
		xenhost_setup_shared_info(*xh);
	xen_setup_mfn_list_list();

	if (suspend_cancelled) {
		xen_start_info->store_mfn =
			pfn_to_mfn(xen_start_info->store_mfn);
		xen_start_info->console.domU.mfn =
			pfn_to_mfn(xen_start_info->console.domU.mfn);
	} else {
#ifdef CONFIG_SMP
		BUG_ON(xen_cpu_initialized_map == NULL);
		cpumask_copy(xen_cpu_initialized_map, cpu_online_mask);
#endif
		xen_vcpu_restore();
	}

	xen_mm_unpin_all();
}
