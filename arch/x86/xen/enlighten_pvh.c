// SPDX-License-Identifier: GPL-2.0
#include <linux/acpi.h>

#include <xen/hvc-console.h>

#include <asm/io_apic.h>
#include <asm/hypervisor.h>
#include <asm/e820/api.h>

#include <xen/xen.h>
#include <xen/xenhost.h>
#include <asm/xen/interface.h>
#include <asm/xen/hypercall.h>

#include <xen/interface/memory.h>

/*
 * PVH variables.
 *
 * The variable xen_pvh needs to live in the data segment since it is used
 * after startup_{32|64} is invoked, which will clear the .bss segment.
 */
bool xen_pvh __attribute__((section(".data"))) = 0;

extern xenhost_ops_t xh_hvm_ops, xh_hvm_nested_ops;

void __init xen_pvh_init(void)
{
	xenhost_t **xh;

	/*
	 * Note: we have already called xen_cpuid_base() in
	 * hypervisor_specific_init()
	 */
	xenhost_register(xenhost_r1, &xh_hvm_ops);

	/*
	 * Detect in some implementation defined manner whether this is
	 * nested or not.
	 */
	if (xen_driver_domain() && xen_nested())
		xenhost_register(xenhost_r2, &xh_hvm_nested_ops);

	xen_pvh = 1;
	xen_start_flags = pvh_start_info.flags;

	for_each_xenhost(xh)
		xenhost_setup_hypercall_page(*xh);
}

void __init mem_map_via_hcall(struct boot_params *boot_params_p)
{
	struct xen_memory_map memmap;
	int rc;

	memmap.nr_entries = ARRAY_SIZE(boot_params_p->e820_table);
	set_xen_guest_handle(memmap.buffer, boot_params_p->e820_table);
	rc = HYPERVISOR_memory_op(XENMEM_memory_map, &memmap);
	if (rc) {
		xen_raw_printk("XENMEM_memory_map failed (%d)\n", rc);
		BUG();
	}
	boot_params_p->e820_entries = memmap.nr_entries;
}
