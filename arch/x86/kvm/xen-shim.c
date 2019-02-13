// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019 Oracle and/or its affiliates. All rights reserved.
 *
 * Xen hypercall emulation shim
 */

#define pr_fmt(fmt) "KVM:" KBUILD_MODNAME ": " fmt

#include <asm/kvm_host.h>

#include <xen/xen.h>
#include <xen/xen-ops.h>
#include <xen/events.h>
#include <xen/xenbus.h>

#define BITS_PER_EVTCHN_WORD (sizeof(xen_ulong_t)*8)

static struct kvm_xen shim = { .domid = XEN_SHIM_DOMID };

static void shim_evtchn_setup(struct shared_info *s)
{
	int cpu;

	/* Point Xen's shared_info to the domain's sinfo page */
	HYPERVISOR_shared_info = s;

	/* Evtchns will be marked pending on allocation */
	memset(s->evtchn_pending, 0, sizeof(s->evtchn_pending));
	/* ... but we do mask all of -- dom0 expect it. */
	memset(s->evtchn_mask, 1, sizeof(s->evtchn_mask));

	for_each_possible_cpu(cpu) {
		struct vcpu_info *vcpu_info;
		int i;

		/* Direct CPU mapping as far as dom0 is concerned */
		per_cpu(xen_vcpu_id, cpu) = cpu;

		vcpu_info = &per_cpu(xen_vcpu_info, cpu);
		memset(vcpu_info, 0, sizeof(*vcpu_info));

		vcpu_info->evtchn_upcall_mask = 0;

		vcpu_info->evtchn_upcall_pending = 0;
		for (i = 0; i < BITS_PER_EVTCHN_WORD; i++)
			clear_bit(i, &vcpu_info->evtchn_pending_sel);

		per_cpu(xen_vcpu, cpu) = vcpu_info;
	}
}

static int __init shim_register(void)
{
	struct shared_info *shinfo;

	shinfo = (struct shared_info *)get_zeroed_page(GFP_KERNEL);
	if (!shinfo) {
		pr_err("Failed to allocate shared_info page\n");
		return -ENOMEM;
	}
	shim.shinfo = shinfo;

	idr_init(&shim.port_to_evt);
	mutex_init(&shim.xen_lock);

	kvm_xen_register_lcall(&shim);

	/* We can handle hypercalls after this point */
	xen_shim_domain = 1;

	shim_evtchn_setup(shim.shinfo);

	xen_setup_features();

	xen_init_IRQ();

	xenbus_init();

	return 0;
}

static int __init shim_init(void)
{
	if (xen_domain())
		return -ENODEV;

	return shim_register();
}

static void __exit shim_exit(void)
{
	xenbus_deinit();
	xen_shim_domain = 0;

	kvm_xen_unregister_lcall();
	HYPERVISOR_shared_info = NULL;
	free_page((unsigned long) shim.shinfo);
	shim.shinfo = NULL;
}

module_init(shim_init);
module_exit(shim_exit)

MODULE_AUTHOR("Ankur Arora <ankur.a.arora@oracle.com>,"
	      "Joao Martins <joao.m.martins@oracle.com>");
MODULE_LICENSE("GPL");
